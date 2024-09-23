#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <errno.h>

#include <json-c/json.h>
#include <curl/curl.h>
#include <event2/event.h>
#include <event2/buffer.h>

#ifdef HAVE_SYS_UTSNAME_H
# include <sys/utsname.h>
#endif

#include "proto/clienttoken.pb-c.h"
#include "proto/login5.pb-c.h"
#include "librespot-c-internal.h"

#define MAX_HEADERS 16
#define HTTP_CLIENT_TIMEOUT 5

#define SPOTIFY_CLIENT_ID_HEX "65b708073fc0480ea92a077233ca87bd" // ClientIdHex from client_id.go

static struct sp_err_map warning_map[] = {
  { SPOTIFY__LOGIN5__V3__LOGIN_RESPONSE__WARNINGS__UNKNOWN_WARNING, "Unknown warning" },
  { SPOTIFY__LOGIN5__V3__LOGIN_RESPONSE__WARNINGS__DEPRECATED_PROTOCOL_VERSION, "Deprecated protocol" },
};

static struct sp_err_map error_map[] = {
  { SPOTIFY__LOGIN5__V3__LOGIN_ERROR__UNKNOWN_ERROR, "Unknown error" },
  { SPOTIFY__LOGIN5__V3__LOGIN_ERROR__INVALID_CREDENTIALS, "Invalid credentials" },
  { SPOTIFY__LOGIN5__V3__LOGIN_ERROR__BAD_REQUEST, "Bad request" },
  { SPOTIFY__LOGIN5__V3__LOGIN_ERROR__UNSUPPORTED_LOGIN_PROTOCOL, "Unsupported login protocol" },
  { SPOTIFY__LOGIN5__V3__LOGIN_ERROR__TIMEOUT, "Timeout" },
  { SPOTIFY__LOGIN5__V3__LOGIN_ERROR__UNKNOWN_IDENTIFIER, "Unknown identifier" },
  { SPOTIFY__LOGIN5__V3__LOGIN_ERROR__TOO_MANY_ATTEMPTS, "Too many attempts" },
  { SPOTIFY__LOGIN5__V3__LOGIN_ERROR__INVALID_PHONENUMBER, "Invalid phonenumber" },
  { SPOTIFY__LOGIN5__V3__LOGIN_ERROR__TRY_AGAIN_LATER, "Try again later" },
};

struct http_client_req
{
  char *user_agent;
  char *url;
  char *output_headers[MAX_HEADERS];
  uint8_t *output_data;
  size_t output_data_len;

  bool headers_only;

  struct evbuffer *input_body;
  int response_code;
};

struct http_client_session
{
  CURL *curl;
};

struct token
{
  char value[512]; // base64 string, actual size 360 bytes
  int32_t expires_after_seconds;
  int32_t refresh_after_seconds;
};

struct http_session
{
  struct token clienttoken;
  struct token accesstoken;
};

static const char *
err2txt(int err, struct sp_err_map *map, size_t map_size)
{
  for (int i = 0; i < map_size; i++)
    {
      if (err == map[i].errorcode)
        return map[i].errmsg;
    }

  return "(unknown error code)";
}

static size_t
curl_request_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  size_t realsize;
  struct http_client_req *req;
  int ret;

  realsize = size * nmemb;
  req = (struct http_client_req *)userdata;

  if (!req->input_body)
    return realsize;

  ret = evbuffer_add(req->input_body, ptr, realsize);
  if (ret < 0)
    {
      printf("Error adding reply from %s to input buffer\n", req->url);
      return 0;
    }

  return realsize;
}

static int
http_client_request(struct http_client_req *req, struct http_client_session *session)
{
  CURL *curl;
  CURLcode res;
  struct curl_slist *headers;
  char header[1024];
  long response_code;
  char **ptr;

  if (session)
    {
      curl = session->curl;
      curl_easy_reset(curl);
    }
  else
    {
      curl = curl_easy_init();
    }

  if (!curl)
    {
      printf("Error: Could not get curl handle\n");
      return -1;
    }

  if (req->user_agent)
    curl_easy_setopt(curl, CURLOPT_USERAGENT, req->user_agent);
  
  curl_easy_setopt(curl, CURLOPT_URL, req->url);

  for (headers = NULL, ptr = req->output_headers; *ptr; ptr++)
    {
      headers = curl_slist_append(headers, *ptr);
    }

  if (headers)
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req->output_data);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, req->output_data_len);

  curl_easy_setopt(curl, CURLOPT_TIMEOUT, HTTP_CLIENT_TIMEOUT);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_request_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, req);

  // Allow redirects
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
  curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5);

  printf("Making request for %s\n", req->url);

  res = curl_easy_perform(curl);
  if (res != CURLE_OK)
    {
      printf("Request to %s failed: %s\n", req->url, curl_easy_strerror(res));
      curl_slist_free_all(headers);
      if (!session)
	{
	  curl_easy_cleanup(curl);
	}
      return -1;
    }

  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
  req->response_code = (int) response_code;
//  curl_headers_save(req->input_headers, curl);

  curl_slist_free_all(headers);
  if (!session)
    {
      curl_easy_cleanup(curl);
    }

  return 0;
}

// Ref. session/clienttoken.go
static ssize_t
msg_make_clienttoken(uint8_t *out, size_t out_len)
{
  Spotify__Clienttoken__Http__V0__ClientTokenRequest treq = SPOTIFY__CLIENTTOKEN__HTTP__V0__CLIENT_TOKEN_REQUEST__INIT;
  Spotify__Clienttoken__Http__V0__ClientDataRequest dreq = SPOTIFY__CLIENTTOKEN__HTTP__V0__CLIENT_DATA_REQUEST__INIT;
  Spotify__Clienttoken__Data__V0__ConnectivitySdkData sdk_data = SPOTIFY__CLIENTTOKEN__DATA__V0__CONNECTIVITY_SDK_DATA__INIT;
  Spotify__Clienttoken__Data__V0__PlatformSpecificData platform_data = SPOTIFY__CLIENTTOKEN__DATA__V0__PLATFORM_SPECIFIC_DATA__INIT;
  ssize_t len;

#ifdef HAVE_SYS_UTSNAME_H
  Spotify__Clienttoken__Data__V0__NativeDesktopMacOSData desktop_macos = SPOTIFY__CLIENTTOKEN__DATA__V0__NATIVE_DESKTOP_MAC_OSDATA__INIT;
  Spotify__Clienttoken__Data__V0__NativeDesktopLinuxData desktop_linux = SPOTIFY__CLIENTTOKEN__DATA__V0__NATIVE_DESKTOP_LINUX_DATA__INIT;
  struct utsname uts = { 0 };

  uname(&uts);
  if (uts.sysname && strcmp(uts.sysname, "Linux") == 0)
    {
      desktop_linux.system_name = uts.sysname;
      desktop_linux.system_release = uts.release;
      desktop_linux.system_version = uts.version;
      desktop_linux.hardware = uts.machine;
      platform_data.desktop_linux = &desktop_linux;
      platform_data.data_case = SPOTIFY__CLIENTTOKEN__DATA__V0__PLATFORM_SPECIFIC_DATA__DATA_DESKTOP_LINUX;
    }
  else if (uts.sysname && strcmp(uts.sysname, "Darwin") == 0)
    {
      desktop_macos.system_version = uts.version;
      desktop_macos.hw_model = uts.machine;
      desktop_macos.compiled_cpu_type = uts.machine;
      platform_data.desktop_macos = &desktop_macos;
      platform_data.data_case = SPOTIFY__CLIENTTOKEN__DATA__V0__PLATFORM_SPECIFIC_DATA__DATA_DESKTOP_MACOS;
    }
#endif

  sdk_data.platform_specific_data = &platform_data; 
  sdk_data.device_id = sp_sysinfo.device_id; //"bcbae1f3062baac486045f13935c6c95ad4191ff";

  dreq.connectivity_sdk_data = &sdk_data;
  dreq.data_case = SPOTIFY__CLIENTTOKEN__HTTP__V0__CLIENT_DATA_REQUEST__DATA_CONNECTIVITY_SDK_DATA; 
  dreq.client_version = sp_sysinfo.client_version; // "0.0.0"; // SpotifyLikeClient
  dreq.client_id = SPOTIFY_CLIENT_ID_HEX;

  treq.client_data = &dreq;
  treq.request_type = SPOTIFY__CLIENTTOKEN__HTTP__V0__CLIENT_TOKEN_REQUEST_TYPE__REQUEST_CLIENT_DATA_REQUEST;
  treq.request_case = SPOTIFY__CLIENTTOKEN__HTTP__V0__CLIENT_TOKEN_REQUEST__REQUEST_CLIENT_DATA;

  len = spotify__clienttoken__http__v0__client_token_request__get_packed_size(&treq);
  if (len > out_len)
    {
      return -1;
    }

  spotify__clienttoken__http__v0__client_token_request__pack(&treq, out);

  return len;
}

// Ref. login5/login5.go
static ssize_t
msg_make_login5(uint8_t *out, size_t out_len, const char *username, uint8_t *stored_cred, size_t stored_cred_len)
{
  Spotify__Login5__V3__LoginRequest req = SPOTIFY__LOGIN5__V3__LOGIN_REQUEST__INIT;
  Spotify__Login5__V3__ClientInfo client_info = SPOTIFY__LOGIN5__V3__CLIENT_INFO__INIT;
  Spotify__Login5__V3__Credentials__StoredCredential stored_credential = SPOTIFY__LOGIN5__V3__CREDENTIALS__STORED_CREDENTIAL__INIT;
  ssize_t len;

  client_info.client_id = SPOTIFY_CLIENT_ID_HEX;
  client_info.device_id = sp_sysinfo.device_id;

  req.client_info = &client_info;

  stored_credential.username = (char *)username;
  stored_credential.data.data = stored_cred;
  stored_credential.data.len = stored_cred_len;

  req.login_method_case = SPOTIFY__LOGIN5__V3__LOGIN_REQUEST__LOGIN_METHOD_STORED_CREDENTIAL;
  req.stored_credential = &stored_credential;

  len = spotify__login5__v3__login_request__get_packed_size(&req);
  if (len > out_len)
    {
      return -1;
    }

  spotify__login5__v3__login_request__pack(&req, out);

  return len;
}

static int
response_read_clienttoken(struct http_session *session, uint8_t *in, size_t in_len)
{
  struct token *token = &session->clienttoken;
  Spotify__Clienttoken__Http__V0__ClientTokenResponse *response;

  response = spotify__clienttoken__http__v0__client_token_response__unpack(NULL, in_len, in);
  if (!response)
    goto error;

  if (response->response_type == SPOTIFY__CLIENTTOKEN__HTTP__V0__CLIENT_TOKEN_RESPONSE_TYPE__RESPONSE_GRANTED_TOKEN_RESPONSE)
    {
      snprintf(token->value, sizeof(token->value), "%s", response->granted_token->token);
      // TODO check truncation
      token->expires_after_seconds = response->granted_token->expires_after_seconds;
      token->refresh_after_seconds = response->granted_token->refresh_after_seconds;
    }
  else if (response->response_type == SPOTIFY__CLIENTTOKEN__HTTP__V0__CLIENT_TOKEN_RESPONSE_TYPE__RESPONSE_CHALLENGES_RESPONSE)
  {
    printf("Not supported");
    goto error;
  }
  else
    goto error;

  spotify__clienttoken__http__v0__client_token_response__free_unpacked(response, NULL);
  return 0;

 error:
  spotify__clienttoken__http__v0__client_token_response__free_unpacked(response, NULL);
  return -1;
}  

static int
response_read_login5(struct http_session *session, uint8_t *in, size_t in_len)
{
  struct token *token = &session->accesstoken;
  Spotify__Login5__V3__LoginResponse *response;

  response = spotify__login5__v3__login_response__unpack(NULL, in_len, in);
  if (!response)
    goto error;

  if (response->n_warnings > 0)
    printf("Got %zu login warnings, first was %d\n", response->n_warnings, response->warnings[0]);

  switch (response->response_case)
    {
      case SPOTIFY__LOGIN5__V3__LOGIN_RESPONSE__RESPONSE_OK:
        printf("Login ok, access token %s\n", response->ok->access_token);
        snprintf(token->value, sizeof(token->value), "%s", response->ok->access_token);
        // TODO check truncation
        token->expires_after_seconds = response->ok->access_token_expires_in;
        break;
      case SPOTIFY__LOGIN5__V3__LOGIN_RESPONSE__RESPONSE_ERROR:
        printf("Login error: %s\n", err2txt(response->error, error_map, sizeof(error_map)/sizeof(error_map[0])));
        break;
      case SPOTIFY__LOGIN5__V3__LOGIN_RESPONSE__RESPONSE_CHALLENGES:
        printf("Login %zu challenges\n", response->challenges->n_challenges);
        // TODO support hashcash challenges
        break;
    }

  spotify__login5__v3__login_response__free_unpacked(response, NULL);
  return 0;

 error:
  spotify__login5__v3__login_response__free_unpacked(response, NULL);
  return -1;
}

int
librespot_http_test(const char *username, uint8_t *stored_cred, size_t stored_cred_len)
{
  struct http_client_req req = { 0 };
  struct http_session session = { 0 };
  int ret;
  uint8_t *msg;
  size_t msg_len = 8192;
  uint8_t *in;
  size_t in_len;
  ssize_t len;

  msg = malloc(msg_len);

  len = msg_make_clienttoken(msg, msg_len);

  req.url = "https://clienttoken.spotify.com/v1/clienttoken";
  req.output_data = msg;
  req.output_data_len = len;

  req.input_body = evbuffer_new();

  sp_cb.hexdump("ClientToken request\n", req.output_data, req.output_data_len);

  req.user_agent = "librespot1.2.3";
  req.output_headers[0] = "Accept: application/x-protobuf";
  req.output_headers[1] = "Content-Type: application/x-protobuf";
  ret = http_client_request(&req, NULL);
  if (ret < 0)
    goto error;

  printf("Result of request is %d\n", req.response_code);
  if (req.response_code != 200)
    goto error;

  in = evbuffer_pullup(req.input_body, -1);
  in_len = evbuffer_get_length(req.input_body);

  ret = response_read_clienttoken(&session, in, in_len);
  if (ret < 0)
    goto error;

  evbuffer_drain(req.input_body, -1);

  req.url = "https://login5.spotify.com/v3/login";
//  req.url = "http://gyfgafguf.dk/skibidi";

  char header[600];
  snprintf(header, sizeof(header), "Client-Token: %s", session.clienttoken.value);
  req.output_headers[2] = header;

  len = msg_make_login5(msg, msg_len, username, stored_cred, stored_cred_len);

  req.output_data = msg;
  req.output_data_len = len;

  sp_cb.hexdump("Login5 request\n", req.output_data, req.output_data_len);

  ret = http_client_request(&req, NULL);

  printf("Result of request is %d\n", req.response_code);
  if (req.response_code != 200)
    goto error;

  in = evbuffer_pullup(req.input_body, -1);
  in_len = evbuffer_get_length(req.input_body);

  ret = response_read_login5(&session, in, in_len);
  if (ret < 0)
    goto error;

  evbuffer_drain(req.input_body, -1);

 error:
  return ret;
// Do login5

// Get challenge
// Find host name
// 
}

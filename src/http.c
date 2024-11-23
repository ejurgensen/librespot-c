#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/param.h>
#include <sys/types.h>
#include <errno.h>

#include <event2/event.h>
#include <curl/curl.h>

#include "librespot-c-internal.h"
#include "http.h"

// Number of seconds the client will wait for a response before aborting
#define HTTP_CLIENT_TIMEOUT 8

struct http_session
{
  CURL *curl;
};

void
http_session_init(struct http_session *session)
{
  session->curl = curl_easy_init();
}

void
http_session_deinit(struct http_session *session)
{
  curl_easy_cleanup(session->curl);
}

void
http_request_free(struct http_request *req, bool only_content)
{
  int i;

  if (!req)
    return;

  free(req->url);
  free(req->body);

  for (i = 0; req->headers[i]; i++)
    free(req->headers[i]);

  if (only_content)
    memset(req, 0, sizeof(struct http_request));
  else
    free(req);
}

void
http_response_free(struct http_response *res, bool only_content)
{
  int i;

  if (!res)
    return;

  free(res->body);

  for (i = 0; res->headers[i]; i++)
    free(res->headers[i]);

  if (only_content)
    memset(res, 0, sizeof(struct http_response));
  else
    free(res);
}

static size_t
header_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  struct http_response *response = userdata;
  uint8_t *new;
  int i;

  if (size * nmemb == 0 || size != 1)
    return 0;

  new = calloc(nmemb + 1, 1); // Extra byte for null termination
  if (!new)
    return 0;

  memcpy(new, ptr, nmemb);
  for (i = 0; i < HTTP_MAX_HEADERS && response->headers[i]; i++)
    ; // Find next free spot in the array
  if (i != HTTP_MAX_HEADERS)
    response->headers[i] = new;
  else
    free(new); // Just discard headers if more than HTTP_MAX_HEADERS

  return nmemb;
}

static size_t
body_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  struct http_response *response = userdata;
  size_t realsize = size * nmemb;
  uint8_t *new;

  if (realsize == 0)
    {
      return 0;
    }

  new = realloc(response->body, response->body_len + realsize + 1);
  if (!new)
    {
      free(response->body);
      response->body = NULL;
      response->body_len = 0;
      return 0;
    }

  memcpy(new + response->body_len, ptr, realsize);
  response->body_len += realsize;

  memset(new + response->body_len, 0, 1); // Zero terminate in case we need to address as C string
  response->body = new;
  return response->body_len;
}

int
http_request(struct http_response *response, struct http_request *request, struct http_session *session)
{
  CURL *curl;
  CURLcode res;
  struct curl_slist *headers = NULL;
  long response_code;
  long opt;
  curl_off_t content_length;
  int i;
  int ret;

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
    RETURN_ERROR(SP_ERR_OOM, "Error allocating CURL handle");

  memset(response, 0, sizeof(struct http_response));

  curl_easy_setopt(curl, CURLOPT_URL, request->url);

  // Set optional params
  if (request->user_agent)
    curl_easy_setopt(curl, CURLOPT_USERAGENT, request->user_agent);
  for (i = 0; i < HTTP_MAX_HEADERS && request->headers[i]; i++)
    headers = curl_slist_append(headers, request->headers[i]);
  if (headers)
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  if ((opt = request->ssl_verify_peer))
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, opt);

  if (request->headers_only)
    {
      curl_easy_setopt(curl, CURLOPT_NOBODY, 1L); // Makes curl make a HEAD request
    }
  else if (request->body && request->body_len > 0)
    {
      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request->body);
      curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, request->body_len);
    }

  curl_easy_setopt(curl, CURLOPT_TIMEOUT, HTTP_CLIENT_TIMEOUT);

  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, body_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_cb);
  curl_easy_setopt(curl, CURLOPT_HEADERDATA, response);

  // Allow redirects
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
  curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5);

  // sp_cb.logmsg("Making request for %s\n", req->url);

  res = curl_easy_perform(curl);
  if (res != CURLE_OK)
    RETURN_ERROR(SP_ERR_NOCONNECTION, curl_easy_strerror(res));

  res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
  response->code = (res == CURLE_OK) ? (int) response_code : -1;

  res = curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &content_length);
  response->content_length = (res == CURLE_OK) ? (ssize_t)content_length : -1;

  curl_slist_free_all(headers);
  if (!session)
    curl_easy_cleanup(curl);

  return 0;

 error:
  curl_slist_free_all(headers);
  if (!session)
    curl_easy_cleanup(curl);

  return ret;
}

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/http.h>
#include <event2/keyvalq_struct.h>

#include "test2_mdns.h"
#include "tests/utils.h"
#include "librespot-c.h"

#define LISTEN_PORT 44500
#define ENDPOINT "/spconnect"
#define DEVICE_ID "0add5a351410381485e36adbb5d6bcbee3be8baa"
#define SPEAKER_NAME "TestSpeaker"

struct cmdarg
{
  struct sp_session *session;
  struct sp_sysinfo *sysinfo;
  struct sp_credentials *credentials;
};

static void
dump_req(struct evhttp_request *req)
{
	const char *cmdtype;
	struct evkeyvalq *headers;
	struct evkeyval *header;
	struct evbuffer *buf;
	char cbuf[256];
	int n;

	switch (evhttp_request_get_command(req)) {
	case EVHTTP_REQ_GET: cmdtype = "GET"; break;
	case EVHTTP_REQ_POST: cmdtype = "POST"; break;
	case EVHTTP_REQ_HEAD: cmdtype = "HEAD"; break;
	case EVHTTP_REQ_PUT: cmdtype = "PUT"; break;
	case EVHTTP_REQ_DELETE: cmdtype = "DELETE"; break;
	case EVHTTP_REQ_OPTIONS: cmdtype = "OPTIONS"; break;
	case EVHTTP_REQ_TRACE: cmdtype = "TRACE"; break;
	case EVHTTP_REQ_CONNECT: cmdtype = "CONNECT"; break;
	case EVHTTP_REQ_PATCH: cmdtype = "PATCH"; break;
	default: cmdtype = "unknown"; break;
	}

	printf("Received a %s request for %s\nHeaders:\n",
	    cmdtype, evhttp_request_get_uri(req));

	headers = evhttp_request_get_input_headers(req);
	for (header = headers->tqh_first; header;
	    header = header->next.tqe_next) {
		printf("  %s: %s\n", header->key, header->value);
	}

	buf = evhttp_request_get_input_buffer(req);
	n = evbuffer_copyout(buf, cbuf, sizeof(cbuf));
	puts("Input data: <<<");
	if (n > 0)
		(void) fwrite(cbuf, 1, n, stdout);
	puts(">>>");
}

static void
request_gen_cb(struct evhttp_request *req, void *arg)
{
  dump_req(req);
  evhttp_send_reply(req, 200, "OK", NULL);
}

static void
response_json_send(struct evhttp_request *req, uint8_t *data, size_t data_len)
{
  struct evbuffer *response = evhttp_request_get_output_buffer(req);
  char cbuf[256];
  int n;

  evbuffer_add(response, data, data_len);

  n = evbuffer_copyout(response, cbuf, sizeof(cbuf));
  puts("Output data: <<<");
  if (n > 0)
    (void) fwrite(cbuf, 1, n, stdout);
  puts(">>>");

  evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/json");
  evhttp_send_reply(req, 200, "OK", response);
}

static void
request_getinfo(struct evhttp_request *req, struct sp_sysinfo *sysinfo, struct sp_credentials *credentials)
{
  uint8_t *data;
  size_t data_len;
  int ret;

  dump_req(req);

  ret = librespotc_connect_getinfo(&data, &data_len, sysinfo, credentials);
  if (ret < 0)
    {
      printf("Error: %s\n", librespotc_last_errmsg());
      goto error;
    }

  response_json_send(req, data, data_len);
  return;

 error:
  evhttp_send_error(req, 500, "Internal error");
}

static void
request_adduser(struct evhttp_request *req, struct sp_session *session)
{
  struct evbuffer *buf;
  struct evbuffer *response;
  char *body;
  uint8_t *data;
  size_t data_len;
  int ret;

  dump_req(req);

  buf = evhttp_request_get_input_buffer(req);
  if (!buf)
    goto error;

  // 0-terminate for safety
  evbuffer_add(buf, "", 1);

  body = (char *) evbuffer_pullup(buf, -1);
  if (!body)
    goto error;

  ret = librespotc_connect_adduser(&data, &data_len, body, session);
  if (ret < 0)
    {
      printf("Error: %s\n", librespotc_last_errmsg());
      goto error;
    }

  response_json_send(req, data, data_len);
  return;

 error:
  evhttp_send_error(req, 500, "Internal Server Error");
}

static void
request_spconnect_cb(struct evhttp_request *req, void *arg)
{
  struct cmdarg *cbarg = arg;
  enum evhttp_cmd_type method;
  const char *uri;

  method = evhttp_request_get_command(req);
  uri = evhttp_request_get_uri(req);

  if (method == EVHTTP_REQ_GET && strstr(uri, "action=getInfo") > 0)
    request_getinfo(req, cbarg->sysinfo, cbarg->credentials);
  else if (method == EVHTTP_REQ_POST)
    request_adduser(req, cbarg->session);
  else
    request_gen_cb(req, arg);
}

static int
announce_librespot(void)
{
  char *txtrecord[10];
  char records[9][128];

  for (int i = 0; i < (sizeof(records) / sizeof(records[0])); i++)
    {
      memset(records[i], 0, 128);
      txtrecord[i] = records[i];
    }

  snprintf(txtrecord[0], 128, "CPath=%s", ENDPOINT);
  snprintf(txtrecord[1], 128, "VERSION=1.0");
  txtrecord[2] = NULL;

  return mdns_register(SPEAKER_NAME, "_spotify-connect._tcp", LISTEN_PORT, txtrecord);
}

struct sp_callbacks callbacks =
{
  .https_get = https_get,
  .tcp_connect = tcp_connect,
  .tcp_disconnect = tcp_disconnect,

  .thread_name_set = NULL,

  .hexdump  = hexdump,
  .logmsg   = logmsg,
};

int
main(int argc, char * argv[])
{
  struct sp_session *session = NULL;
  struct sp_sysinfo sysinfo;
  struct sp_credentials credentials;
  struct event_base *evbase = NULL;
  struct evhttp *evhttp = NULL;
  struct cmdarg cbarg;
  int ret;

  if (argc != 3)
    {
      printf("%s username password|token\n", argv[0]);
      goto error;
    }

  memset(&sysinfo, 0, sizeof(struct sp_sysinfo));
  snprintf(sysinfo.device_id, sizeof(sysinfo.device_id), DEVICE_ID);
  snprintf(sysinfo.speaker_name, sizeof(sysinfo.speaker_name), SPEAKER_NAME);

  ret = librespotc_init(&sysinfo, &callbacks);
  if (ret < 0)
    {
      printf("Error initializing Spotify: %s\n", librespotc_last_errmsg());
      goto error;
    }

  if (strlen(argv[2]) < 100)
    session = librespotc_login_password(argv[1], argv[2]);
  else
    session = librespotc_login_token(argv[1], argv[2]); // Length of token should be 194
  if (!session)
    {
      printf("Error logging in: %s\n", librespotc_last_errmsg());
      goto error;
    }

  printf("\n --- Login OK --- \n");

  ret = librespotc_credentials_get(&credentials, session);
  if (ret < 0)
    {
      printf("Error getting session credentials: %s\n", librespotc_last_errmsg());
      goto error;
    }

  printf("Username is %s\n", credentials.username);

  ret = librespotc_connect_hello(session);
  if (ret < 0)
    {
      printf("Error sending Spotify Connect hello: %s\n", librespotc_last_errmsg());
      goto error;
    }

  evbase = event_base_new();

  // Create a http server
  evhttp = evhttp_new(evbase);
  cbarg.sysinfo = &sysinfo;
  cbarg.credentials = &credentials;
  cbarg.session = session;
  evhttp_set_cb(evhttp, ENDPOINT, request_spconnect_cb, &cbarg);
  evhttp_set_gencb(evhttp, request_gen_cb, NULL);
  ret = evhttp_bind_socket(evhttp, "0.0.0.0", LISTEN_PORT);
  if (ret < 0)
    {
      printf("Could not bind to %d\n", LISTEN_PORT);
      goto error;
    }

  ret = mdns_init(evbase);
  if (ret < 0)
    goto error;

  announce_librespot();

  printf("Listening for requests on port %d\n", LISTEN_PORT);

  event_base_dispatch(evbase);

  mdns_deinit();
  event_base_free(evbase);
  evhttp_free(evhttp);
  librespotc_logout(session);
  librespotc_deinit();

  return 0;

 error:
  if (evhttp)
    evhttp_free(evhttp);
  if (evbase)
    event_base_free(evbase);
  if (session)
    librespotc_logout(session);
  librespotc_deinit();

  return -1;
}

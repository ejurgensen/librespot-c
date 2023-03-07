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
#define DEVICE_ID "aabbccddeeff"
#define SPEAKER_NAME "MySpeaker"

struct cmdarg
{
  struct sp_sysinfo *sysinfo;
  struct sp_credentials *credentials;
};

static void
request_gen_cb(struct evhttp_request *req, void *arg)
{
	const char *cmdtype;
	struct evkeyvalq *headers;
	struct evkeyval *header;
	struct evbuffer *buf;

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
	puts("Input data: <<<");
	while (evbuffer_get_length(buf)) {
		int n;
		char cbuf[128];
		n = evbuffer_remove(buf, cbuf, sizeof(cbuf));
		if (n > 0)
			(void) fwrite(cbuf, 1, n, stdout);
	}
	puts(">>>");

	evhttp_send_reply(req, 200, "OK", NULL);
}

static void
handle_getinfo(struct evhttp_request *req, struct sp_sysinfo *sysinfo, struct sp_credentials *credentials)
{
  struct evbuffer *response;
  uint8_t *data;
  size_t data_len;

  librespotc_connect_getinfo(&data, &data_len, sysinfo, credentials);

  response = evbuffer_new();
  evbuffer_add(response, data, data_len);

  evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/json");
  evhttp_send_reply(req, 200, "OK", response);
}

static void
request_spconnect_cb(struct evhttp_request *req, void *arg)
{
  struct cmdarg *cbarg = arg;
  const char *uri;

  uri = evhttp_request_get_uri(req);

  if (strstr(uri, "action=getInfo") > 0)
    handle_getinfo(req, cbarg->sysinfo, cbarg->credentials);
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

/*
  if (strlen(argv[3]) < 100)
    session = librespotc_login_password(argv[2], argv[3]);
  else
    session = librespotc_login_token(argv[2], argv[3]); // Length of token should be 194
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
*/
  evbase = event_base_new();

  // Create a http server
  evhttp = evhttp_new(evbase);
  cbarg.sysinfo = &sysinfo;
  cbarg.credentials = &credentials;
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

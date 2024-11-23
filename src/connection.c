#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <errno.h>

#include <json-c/json.h>

#ifdef HAVE_SYS_UTSNAME_H
# include <sys/utsname.h>
#endif

#include "librespot-c-internal.h"
#include "connection.h"
#include "channel.h"
#include "http.h"

#define MERCURY_REQ_SIZE_MAX 4096

static struct timeval sp_idle_tv = { SP_AP_DISCONNECT_SECS, 0 };

static uint8_t sp_aes_iv[] = { 0x72, 0xe0, 0x67, 0xfb, 0xdd, 0xcb, 0xcf, 0x77, 0xeb, 0xe8, 0xbc, 0x64, 0x3f, 0x63, 0x0d, 0x93 };

static struct sp_err_map sp_login_errors[] = {
  { ERROR_CODE__ProtocolError, "Protocol error" },
  { ERROR_CODE__TryAnotherAP, "Try another access point" },
  { ERROR_CODE__BadConnectionId, "Bad connection ID" },
  { ERROR_CODE__TravelRestriction, "Travel restriction" },
  { ERROR_CODE__PremiumAccountRequired, "Premium account required" },
  { ERROR_CODE__BadCredentials, "Bad credentials" },
  { ERROR_CODE__CouldNotValidateCredentials, "Could not validate credentials" },
  { ERROR_CODE__AccountExists, "Account exists" },
  { ERROR_CODE__ExtraVerificationRequired, "Extra verification required" },
  { ERROR_CODE__InvalidAppKey, "Invalid app key" },
  { ERROR_CODE__ApplicationBanned, "Application banned" },
};

static struct sp_err_map sp_login5_warning_map[] = {
  { SPOTIFY__LOGIN5__V3__LOGIN_RESPONSE__WARNINGS__UNKNOWN_WARNING, "Unknown warning" },
  { SPOTIFY__LOGIN5__V3__LOGIN_RESPONSE__WARNINGS__DEPRECATED_PROTOCOL_VERSION, "Deprecated protocol" },
};

static struct sp_err_map sp_login5_error_map[] = {
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

/* ---------------------------------- MOCKING ------------------------------- */

#ifdef DEBUG_MOCK
#include "mock.h"

static int debug_mock_pipe[2];
static int debug_mock_chunks_written = 0;

static int
debug_mock_response(struct sp_message *msg, struct sp_connection *conn)
{
  if (debug_mock_chunks_written == 1)
    return 0; // Only write the chunk once

  switch(msg->type)
    {
      case MSG_TYPE_CLIENT_HELLO:
	write(debug_mock_pipe[1], mock_resp_apresponse, sizeof(mock_resp_apresponse));
	break;
      case MSG_TYPE_CLIENT_RESPONSE_ENCRYPTED:
        memcpy(conn->decrypt.key, mock_recv_key, sizeof(conn->decrypt.key));
	// Spotify will send the replies split in these 6 packets
	write(debug_mock_pipe[1], mock_resp_client_encrypted1, sizeof(mock_resp_client_encrypted1));
	write(debug_mock_pipe[1], mock_resp_client_encrypted2, sizeof(mock_resp_client_encrypted2));
	write(debug_mock_pipe[1], mock_resp_client_encrypted3, sizeof(mock_resp_client_encrypted3));
	write(debug_mock_pipe[1], mock_resp_client_encrypted4, sizeof(mock_resp_client_encrypted4));
	write(debug_mock_pipe[1], mock_resp_client_encrypted5, sizeof(mock_resp_client_encrypted5));
	write(debug_mock_pipe[1], mock_resp_client_encrypted6, sizeof(mock_resp_client_encrypted6));
	break;
      case MSG_TYPE_MERCURY_TRACK_GET:
	write(debug_mock_pipe[1], mock_resp_mercury_req1, sizeof(mock_resp_mercury_req1));
	write(debug_mock_pipe[1], mock_resp_mercury_req2, sizeof(mock_resp_mercury_req2));
	break;
      case MSG_TYPE_AUDIO_KEY_GET:
        memset(conn->decrypt.key, 0, sizeof(conn->decrypt.key)); // Tells msg_read_one() to skip decryption
	write(debug_mock_pipe[1], mock_resp_aeskey, sizeof(mock_resp_aeskey));
	break;
      case MSG_TYPE_CHUNK_REQUEST:
	write(debug_mock_pipe[1], mock_resp_chunk1, sizeof(mock_resp_chunk1));
	write(debug_mock_pipe[1], mock_resp_chunk2, sizeof(mock_resp_chunk2));
	debug_mock_chunks_written++;
	break;
      default:
	break;
    }

  return 0;
}
#endif


/* --------------------------------- Helpers -------------------------------- */

static char *
asprintf_or_die(const char *fmt, ...)
{
  char *ret = NULL;
  va_list va;

  va_start(va, fmt);
  if (vasprintf(&ret, fmt, va) < 0)
    {
      sp_cb.logmsg("Out of memory for asprintf\n");
      abort();
    }
  va_end(va);

  return ret;
}

#ifdef HAVE_SYS_UTSNAME_H
static void
system_info_from_uname(SystemInfo *system_info)
{
  struct utsname uts = { 0 };

  if (uname(&uts) < 0)
    return;

  if (strcmp(uts.sysname, "Linux") == 0)
    system_info->os = OS__OS_LINUX;
  else if (strcmp(uts.sysname, "Darwin") == 0)
    system_info->os = OS__OS_OSX;
  else if (strcmp(uts.sysname, "FreeBSD") == 0)
    system_info->os = OS__OS_FREEBSD;

  if (strcmp(uts.machine, "x86_64") == 0)
    system_info->cpu_family = CPU_FAMILY__CPU_X86_64;
  else if (strncmp(uts.machine, "arm", 3) == 0)
    system_info->cpu_family = CPU_FAMILY__CPU_ARM;
  else if (strcmp(uts.machine, "aarch64") == 0)
    system_info->cpu_family = CPU_FAMILY__CPU_ARM;
  else if (strcmp(uts.machine, "i386") == 0)
    system_info->cpu_family = CPU_FAMILY__CPU_X86;
  else if (strcmp(uts.machine, "i686") == 0)
    system_info->cpu_family = CPU_FAMILY__CPU_X86;
  else if (strcmp(uts.machine, "ppc") == 0)
    system_info->cpu_family = CPU_FAMILY__CPU_PPC;
  else if (strcmp(uts.machine, "ppc64") == 0)
    system_info->cpu_family = CPU_FAMILY__CPU_PPC_64;
}
#else
static void
system_info_from_uname(SystemInfo *system_info)
{
  return;
}
#endif

// Returns true if format of a is preferred over b (and is valid). According to
// librespot comment most podcasts are 96 kbit.
static bool
format_is_preferred(AudioFile *a, AudioFile *b, enum sp_bitrates bitrate_preferred)
{
  if (a->format != AUDIO_FILE__FORMAT__OGG_VORBIS_96 &&
      a->format != AUDIO_FILE__FORMAT__OGG_VORBIS_160 &&
      a->format != AUDIO_FILE__FORMAT__OGG_VORBIS_320)
    return false;

  if (!b)
    return true; // Any format is better than no format

  switch (bitrate_preferred)
    {
      case SP_BITRATE_96:
	return (a->format < b->format); // Prefer lowest
      case SP_BITRATE_160:
	if (b->format == AUDIO_FILE__FORMAT__OGG_VORBIS_160)
	  return false;
	else if (a->format == AUDIO_FILE__FORMAT__OGG_VORBIS_160)
	  return true;
	else
	  return (a->format < b->format); // Prefer lowest
      case SP_BITRATE_320:
	return (a->format > b->format); // Prefer highest
      case SP_BITRATE_ANY:
	return (a->format > b->format); // This case shouldn't happen, so this is mostly to avoid compiler warnings
    }

  return false;
}

int
file_select(uint8_t *out, size_t out_len, Track *track, enum sp_bitrates bitrate_preferred)
{
  AudioFile *selected = NULL;
  AudioFile *file;
  int i;

  for (i = 0; i < track->n_file; i++)
    {
      file = track->file[i];

      if (!file->has_file_id || !file->has_format || file->file_id.len != out_len)
	continue;

      if (format_is_preferred(file, selected, bitrate_preferred))
	selected = file;
    }

  if (!selected)
    return -1;

  memcpy(out, selected->file_id.data, selected->file_id.len);

  return 0;
}

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

/* --------------------------- Connection handling -------------------------- */

static void
tcp_connection_clear(struct sp_connection *conn)
{
  if (!conn)
    return;

  if (conn->response_ev)
    event_free(conn->response_ev);
  if (conn->idle_ev)
    event_free(conn->idle_ev);
  if (conn->timeout_ev)
    event_free(conn->timeout_ev);

  if (conn->handshake_packets)
    evbuffer_free(conn->handshake_packets);
  if (conn->incoming)
    evbuffer_free(conn->incoming);

  free(conn->keys.shared_secret);

  memset(conn, 0, sizeof(struct sp_connection));
  conn->response_fd = -1;
}

static void
tcp_connection_idle_cb(int fd, short what, void *arg)
{
  struct sp_connection *conn = arg;

  ap_disconnect(conn);

  sp_cb.logmsg("Connection is idle, auto-disconnected\n");
}

static int
tcp_connection_make(struct sp_connection *conn, struct sp_server *server, struct sp_conn_callbacks *cb, void *cb_arg)
{
  int response_fd;
  int ret;

#ifndef DEBUG_MOCK
  response_fd = sp_cb.tcp_connect(server->address, server->port);
  if (response_fd < 0)
    RETURN_ERROR(SP_ERR_NOCONNECTION, "Could not connect to access point");
#else
  pipe(debug_mock_pipe);
  response_fd = debug_mock_pipe[0];
#endif

  server->last_connect_ts = time(NULL);
  conn->server = server;

  conn->response_fd = response_fd;
  conn->response_ev = event_new(cb->evbase, response_fd, EV_READ | EV_PERSIST, cb->response_cb, cb_arg);
  conn->timeout_ev = evtimer_new(cb->evbase, cb->timeout_cb, cb_arg);

  conn->idle_ev = evtimer_new(cb->evbase, tcp_connection_idle_cb, conn);

  conn->handshake_packets = evbuffer_new();
  conn->incoming = evbuffer_new();

  crypto_keys_set(&conn->keys);
  conn->encrypt.logmsg = sp_cb.logmsg;
  conn->decrypt.logmsg = sp_cb.logmsg;

  event_add(conn->response_ev, NULL);

  conn->is_connected = true;

  return 0;

 error:
  return ret;
}

void
ap_disconnect(struct sp_connection *conn)
{
  if (conn->is_connected)
    sp_cb.tcp_disconnect(conn->response_fd);

  tcp_connection_clear(conn);
}

enum sp_error
ap_connect(struct sp_connection *conn, struct sp_server *server, time_t *cooldown_ts, struct sp_conn_callbacks *cb, void *cb_arg)
{
  int ret;
  time_t now;

  // Protection against flooding the access points with reconnection attempts
  // Note that cooldown_ts can't be part of the connection struct because
  // the struct is reset between connection attempts.
  now = time(NULL);
  if (now > *cooldown_ts + SP_AP_COOLDOWN_SECS) // Last attempt was a long time ago
    *cooldown_ts = now;
  else if (now >= *cooldown_ts) // Last attempt was recent, so disallow more attempts for a while
    *cooldown_ts = now + SP_AP_COOLDOWN_SECS;
  else
    RETURN_ERROR(SP_ERR_NOCONNECTION, "Cannot connect to access point, cooldown after disconnect is in effect");

  if (conn->is_connected)
    ap_disconnect(conn);

  ret = tcp_connection_make(conn, server, cb, cb_arg);
  if (ret < 0)
    RETURN_ERROR(ret, sp_errmsg);

  return SP_OK_DONE;

 error:
  ap_disconnect(conn);
  return ret;
}


/* ------------------------------ Raw packets ------------------------------- */

static ssize_t
packet_make_encrypted(uint8_t *out, size_t out_len, uint8_t cmd, const uint8_t *payload, size_t payload_len, struct crypto_cipher *cipher)
{
  uint16_t be;
  size_t plain_len;
  ssize_t pkt_len;
  uint8_t *ptr;

  be = htobe16(payload_len);

  plain_len = sizeof(cmd) + sizeof(be) + payload_len;
  if (plain_len > out_len)
    goto error;

  ptr = out;
  memcpy(ptr, &cmd, sizeof(cmd));
  ptr += sizeof(cmd);
  memcpy(ptr, &be, sizeof(be));
  ptr += sizeof(be);
  memcpy(ptr, payload, payload_len);

//  sp_cb.hexdump("Encrypting packet\n", out, plain_len);

  pkt_len = crypto_encrypt(out, out_len, plain_len, cipher);
  if (pkt_len < 9)
    goto error;

  return pkt_len;

 error:
  return -1;
}

static ssize_t
packet_make_plain(uint8_t *out, size_t out_len, uint8_t *protobuf, size_t protobuf_len, bool add_version_header)
{
  const uint8_t version_header[] = { 0x00, 0x04 };
  size_t header_len;
  ssize_t len;
  uint32_t be;

  header_len = add_version_header ? sizeof(be) + sizeof(version_header) : sizeof(be);

  len = header_len + protobuf_len;
  if (len > out_len)
    return -1;

  if (add_version_header)
    memcpy(out, version_header, sizeof(version_header));

  be = htobe32(len);
  memcpy(out + header_len - sizeof(be), &be, sizeof(be)); // Last bytes of the header is the length
  memcpy(out + header_len, protobuf, protobuf_len);

  return len;
}


/* ---------------------------- Mercury messages ---------------------------- */

static void
mercury_free(struct sp_mercury *mercury, int content_only)
{
  int i;

  if (!mercury)
    return;

  free(mercury->uri);
  free(mercury->method);
  free(mercury->content_type);

  for (i = 0; i < mercury->parts_num; i++)
    {
      free(mercury->parts[i].data);

      if (mercury->parts[i].track)
	track__free_unpacked(mercury->parts[i].track, NULL);
    }

  if (content_only)
    memset(mercury, 0, sizeof(struct sp_mercury));
  else
    free(mercury);
}

static int
mercury_parse(struct sp_mercury *mercury, uint8_t *payload, size_t payload_len)
{
  Header *header;
  uint8_t *ptr;
  uint16_t be;
  uint64_t be64;
  uint16_t seq_len;
  uint16_t header_len;
  size_t required_len; // For size checking
  uint8_t flags;
  int i;

  ptr = payload;

  required_len = sizeof(be);
  if (required_len > payload_len)
    goto error_length; // Length check 1

  memcpy(&be, ptr, sizeof(be));
  seq_len = be16toh(be);
  ptr += sizeof(be); // 1: length += sizeof(be)

  required_len += seq_len + sizeof(flags) + sizeof(be) + sizeof(be);
  if (required_len > payload_len || seq_len != sizeof(be64))
    goto error_length; // Length check 2

  memcpy(&be64, ptr, sizeof(be64));
  mercury->seq = be64toh(be64);
  ptr += seq_len; // 2: length += seq_len

  memcpy(&flags, ptr, sizeof(flags));
  ptr += sizeof(flags); // 2: length += sizeof(flags)

  memcpy(&be, ptr, sizeof(be));
  mercury->parts_num = be16toh(be) - 1; // What's the deal with the 1...?
  ptr += sizeof(be); // 2: length += sizeof(be)

  if (mercury->parts_num > SP_MERCURY_MAX_PARTS)
    return -1;

  memcpy(&be, ptr, sizeof(be));
  header_len = be16toh(be);
  ptr += sizeof(be); // 2: length += sizeof(be)

  required_len += header_len;
  if (required_len > payload_len)
    goto error_length; // Length check 3

  header = header__unpack(NULL, header_len, ptr);
  if (!header)
    goto error_length;
  ptr += header_len; // 3: length += header_len

  mercury->uri = header->uri ? strdup(header->uri) : NULL;
  mercury->method = header->method ? strdup(header->method) : NULL;
  mercury->content_type = header->content_type ? strdup(header->content_type) : NULL;

  for (i = 0; i < mercury->parts_num; i++)
    {
      required_len += sizeof(be);
      if (required_len > payload_len)
	goto error_length; // Length check 4

      memcpy(&be, ptr, sizeof(be));
      mercury->parts[i].len = be16toh(be);
      ptr += sizeof(be); // 4: length += sizeof(be)

      required_len += mercury->parts[i].len;
      if (required_len > payload_len)
	goto error_length; // Length check 5

      mercury->parts[i].data = malloc(mercury->parts[i].len);
      memcpy(mercury->parts[i].data, ptr, mercury->parts[i].len);
      ptr += mercury->parts[i].len; // 5: length += mercury->parts[i].len

      mercury->parts[i].track = track__unpack(NULL, mercury->parts[i].len, mercury->parts[i].data);
    }

  header__free_unpacked(header, NULL);

  assert(ptr == payload + required_len);

  return 0;

 error_length:
  mercury_free(mercury, 1);
  return -1;
}


/* ---------------------Request preparation (dependencies) ------------------ */

static enum sp_error
prepare_tcp(struct sp_seq_request *request, struct sp_conn_callbacks *cb, struct sp_session *session)
{
  struct sp_connection *conn = &session->conn;
  int ret;

  if (!conn->is_connected)
    {
      ret = ap_connect(conn, &session->accesspoint, &session->cooldown_ts, cb, session);
      if (ret < 0)
	RETURN_ERROR(ret, sp_errmsg);
    }

  return SP_OK_DONE;

 error:
  return ret;
}

static enum sp_error
prepare_http_auth(struct sp_seq_request *request, struct sp_conn_callbacks *cb, struct sp_session *session)
{
  // TODO check that the tokens aren't expired for login5 and storage-resolve
  return SP_OK_DONE;
}


/* --------------------------- Incoming messages ---------------------------- */

#define SP_AP_RESOLVE_AVOID_SECS 3600

static enum sp_error
resolve_server_info_set(struct sp_server *server, const char *key, json_object *jresponse)
{
  json_object *list;
  json_object *instance;
  const char *s;
  char *colon;
  bool is_same;
  bool has_failed;
  int ret;
  int n;
  int i;

  has_failed = (server->last_failed_ts + SP_AP_RESOLVE_AVOID_SECS > time(NULL));

  if (! (json_object_object_get_ex(jresponse, key, &list) || json_object_get_type(list) == json_type_array))
    RETURN_ERROR(SP_ERR_NOCONNECTION, "No address list in response from access point resolver");

  n = json_object_array_length(list);
  for (i = 0, s = NULL; i < n && !s; i++)
    {
      instance = json_object_array_get_idx(list, i);
      if (! (instance && json_object_get_type(instance) == json_type_string))
        RETURN_ERROR(SP_ERR_NOCONNECTION, "Unexpected data in response from access point resolver");

      s = json_object_get_string(instance); // This string includes the port
      is_same = (server->address && strncmp(s, server->address, strlen(server->address) == 0));

      if (is_same && has_failed)
        s = NULL; // This AP has failed on us recently, so avoid
    }

  if (!s)
    RETURN_ERROR(SP_ERR_NOCONNECTION, "Response from access port resolver had no valid servers");

  if (!is_same)
    {
      free(server->address);
      memset(server, 0, sizeof(struct sp_server));

      server->address = strdup(s);

      colon = strchr(server->address, ':');
      if (colon)
        *colon = '\0';

      server->port = colon ? (unsigned short)atoi(colon + 1) : 443;
    }

  server->last_resolved_ts = time(NULL);
  return SP_OK_DONE;

 error:
  return ret;
}

static enum sp_error
handle_ap_resolve(struct sp_message *msg, struct sp_session *session)
{
  struct http_response *res = &msg->payload.hres;
  json_object *jresponse = NULL;
  int ret;

  if (res->code != 200)
    RETURN_ERROR(SP_ERR_NOCONNECTION, "AP resolver returned an error");

  jresponse = json_tokener_parse(res->body);
  if (!jresponse)
    RETURN_ERROR(SP_ERR_NOCONNECTION, "Could not parse reply from access point resolver");

  ret = resolve_server_info_set(&session->accesspoint, "accesspoint", jresponse);
  if (ret < 0)
    goto error;

  ret = resolve_server_info_set(&session->spclient, "spclient", jresponse);
  if (ret < 0)
    goto error;

  ret = resolve_server_info_set(&session->dealer, "dealer", jresponse);
  if (ret < 0)
    goto error;

  json_object_put(jresponse);
  return SP_OK_DONE;

 error:
  json_object_put(jresponse);
  return ret;
}

static enum sp_error
handle_client_hello(struct sp_message *msg, struct sp_session *session)
{
  uint8_t *payload = msg->payload.tmsg.data;
  size_t payload_len = msg->payload.tmsg.len;
  APResponseMessage *apresponse;
  struct sp_connection *conn = &session->conn;
  int ret;

  // The first 4 bytes should be the size of the message
  if (payload_len < 4)
    RETURN_ERROR(SP_ERR_INVALID, "Invalid apresponse from access point");

  apresponse = apresponse_message__unpack(NULL, payload_len - 4, payload + 4);
  if (!apresponse)
    RETURN_ERROR(SP_ERR_INVALID, "Could not unpack apresponse from access point");

  // TODO check APLoginFailed

  // Not sure if necessary
  if (!apresponse->challenge || !apresponse->challenge->login_crypto_challenge)
    RETURN_ERROR(SP_ERR_INVALID, "Missing challenge in response from access point");

  crypto_shared_secret(
    &conn->keys.shared_secret, &conn->keys.shared_secret_len,
    conn->keys.private_key, sizeof(conn->keys.private_key),
    apresponse->challenge->login_crypto_challenge->diffie_hellman->gs.data, apresponse->challenge->login_crypto_challenge->diffie_hellman->gs.len);

  apresponse_message__free_unpacked(apresponse, NULL);

  conn->handshake_completed = true;

  return SP_OK_DONE;

 error:
  return ret;
}

static enum sp_error
handle_apwelcome(uint8_t *payload, size_t payload_len, struct sp_session *session)
{
  APWelcome *apwelcome;
  int ret;

  apwelcome = apwelcome__unpack(NULL, payload_len, payload);
  if (!apwelcome)
    RETURN_ERROR(SP_ERR_INVALID, "Could not unpack apwelcome response from access point");

  if (apwelcome->reusable_auth_credentials_type == AUTHENTICATION_TYPE__AUTHENTICATION_STORED_SPOTIFY_CREDENTIALS)
    {
      if (apwelcome->reusable_auth_credentials.len > sizeof(session->credentials.stored_cred))
	RETURN_ERROR(SP_ERR_INVALID, "Credentials from Spotify longer than expected");

      session->credentials.stored_cred_len = apwelcome->reusable_auth_credentials.len;
      memcpy(session->credentials.stored_cred, apwelcome->reusable_auth_credentials.data, session->credentials.stored_cred_len);

      // No need for this any more
      memset(session->credentials.password, 0, sizeof(session->credentials.password));
    }

  apwelcome__free_unpacked(apwelcome, NULL);

  return SP_OK_DONE;

 error:
  return ret;
}

static enum sp_error
handle_aplogin_failed(uint8_t *payload, size_t payload_len, struct sp_session *session)
{
  APLoginFailed *aplogin_failed;

  aplogin_failed = aplogin_failed__unpack(NULL, payload_len, payload);
  if (!aplogin_failed)
    {
      sp_errmsg = "Could not unpack login failure from access point";
      return SP_ERR_LOGINFAILED;
    }

  sp_errmsg = err2txt(aplogin_failed->error_code, sp_login_errors, ARRAY_SIZE(sp_login_errors));

  aplogin_failed__free_unpacked(aplogin_failed, NULL);

  return SP_ERR_LOGINFAILED;
}

static enum sp_error
handle_chunk_res(uint8_t *payload, size_t payload_len, struct sp_session *session)
{
  struct sp_channel *channel;
  uint16_t channel_id;
  int ret;

  ret = channel_msg_read(&channel_id, payload, payload_len, session);
  if (ret < 0)
    goto error;

  channel = &session->channels[channel_id];

  // Save any audio data to a buffer that will be written to audio_fd[1] when
  // it is writable. Note that request for next chunk will also happen then.
  evbuffer_add(channel->audio_buf, channel->body.data, channel->body.data_len);

//  sp_cb.logmsg("EOC is %d, data is %zu, buflen is %zu\n", channel->file.end_of_chunk, channel->body.data_len, evbuffer_get_length(channel->audio_buf));

  return channel->file.end_of_chunk ? SP_OK_DATA : SP_OK_OTHER;

 error:
  return ret;
}

static enum sp_error
handle_aes_key(uint8_t *payload, size_t payload_len, struct sp_session *session)
{
  struct sp_channel *channel;
  const char *errmsg;
  uint32_t be32;
  uint32_t channel_id;
  int ret;

  // Payload is expected to consist of seq (uint32 BE), and key (16 bytes)
  if (payload_len != sizeof(be32) + 16)
    RETURN_ERROR(SP_ERR_DECRYPTION, "Unexpected key received");

  memcpy(&be32, payload, sizeof(be32));
  channel_id = be32toh(be32);

  channel = channel_get(channel_id, session);
  if (!channel)
    RETURN_ERROR(SP_ERR_INVALID, "Unexpected channel received");

  memcpy(channel->file.key, payload + 4, 16);

  ret = crypto_aes_new(&channel->file.decrypt, channel->file.key, sizeof(channel->file.key), sp_aes_iv, sizeof(sp_aes_iv), &errmsg);
  if (ret < 0)
    RETURN_ERROR(SP_ERR_DECRYPTION, errmsg);

  return SP_OK_DONE;

 error:
  return ret;
}

static enum sp_error
handle_aes_key_error(uint8_t *payload, size_t payload_len, struct sp_session *session)
{
  sp_errmsg = "Did not get key for decrypting track";

  return SP_ERR_DECRYPTION;
}

// AP in bad state may return a channel error after chunk request. In that case
// we error with NOCONNECTION, because that will make the main session handler
// (see response_cb) retry with another access point. An example of this issue
// is here https://github.com/librespot-org/librespot/issues/972
static enum sp_error
handle_channel_error(uint8_t *payload, size_t payload_len, struct sp_session *session)
{
  sp_errmsg = "The accces point returned a channel error";

  return SP_ERR_NOCONNECTION;
}

static enum sp_error
handle_mercury_req(uint8_t *payload, size_t payload_len, struct sp_session *session)
{
  struct sp_mercury mercury = { 0 };
  struct sp_channel *channel;
  uint32_t channel_id;
  int ret;

  ret = mercury_parse(&mercury, payload, payload_len);
  if (ret < 0)
    {
      sp_errmsg = "Could not parse message from Spotify";
      return SP_ERR_INVALID;
    }

  if (mercury.parts_num != 1 || !mercury.parts[0].track)
    RETURN_ERROR(SP_ERR_INVALID, "Unexpected track response from Spotify");

  channel_id = (uint32_t)mercury.seq;

  channel = channel_get(channel_id, session);
  if (!channel)
    RETURN_ERROR(SP_ERR_INVALID, "Unexpected channel received");

  ret = file_select(channel->file.id, sizeof(channel->file.id), mercury.parts[0].track, session->bitrate_preferred);
  if (ret < 0)
    RETURN_ERROR(SP_ERR_INVALID, "Could not find track data");

  mercury_free(&mercury, 1);

  return SP_OK_DONE; // Continue to get AES key

 error:
  mercury_free(&mercury, 1);
  return ret;
}

static enum sp_error
handle_ping(uint8_t *payload, size_t payload_len, struct sp_session *session)
{
  msg_pong(session);

  return SP_OK_OTHER;
}

static enum sp_error
handle_clienttoken(struct sp_message *msg, struct sp_session *session)
{
  struct http_response *hres = &msg->payload.hres;
  struct sp_token *token = &session->http_clienttoken;
  Spotify__Clienttoken__Http__V0__ClientTokenResponse *response;
  int ret;

  response = spotify__clienttoken__http__v0__client_token_response__unpack(NULL, hres->body_len, hres->body);
  if (!response)
    RETURN_ERROR(SP_ERR_INVALID, "Could not parse clienttoken response");

  if (response->response_type == SPOTIFY__CLIENTTOKEN__HTTP__V0__CLIENT_TOKEN_RESPONSE_TYPE__RESPONSE_GRANTED_TOKEN_RESPONSE)
    {
      snprintf(token->value, sizeof(token->value), "%s", response->granted_token->token);
      // TODO check truncation
      token->expires_after_seconds = response->granted_token->expires_after_seconds;
      token->refresh_after_seconds = response->granted_token->refresh_after_seconds;
      // TODO check and refresh
    }
  else if (response->response_type == SPOTIFY__CLIENTTOKEN__HTTP__V0__CLIENT_TOKEN_RESPONSE_TYPE__RESPONSE_CHALLENGES_RESPONSE)
    RETURN_ERROR(SP_ERR_INVALID, "Unsupported clienttoken response");
  else
    RETURN_ERROR(SP_ERR_INVALID, "Unknown clienttoken response");

  spotify__clienttoken__http__v0__client_token_response__free_unpacked(response, NULL);
  return SP_OK_DONE;

 error:
  spotify__clienttoken__http__v0__client_token_response__free_unpacked(response, NULL);
  return ret;
}

static enum sp_error
handle_login5(struct sp_message *msg, struct sp_session *session)
{
  struct http_response *hres = &msg->payload.hres;
  struct sp_token *token = &session->http_accesstoken;
  Spotify__Login5__V3__LoginResponse *response;
  int ret;
  int i;

  response = spotify__login5__v3__login_response__unpack(NULL, hres->body_len, hres->body);
  if (!response)
    RETURN_ERROR(SP_ERR_INVALID, "Could not parse login5 response");

  for (i = 0; i < response->n_warnings; i++)
    sp_cb.logmsg("Got login5 warning '%s'", err2txt(response->warnings[i], sp_login5_warning_map, ARRAY_SIZE(sp_login5_warning_map)));

  switch (response->response_case)
    {
      case SPOTIFY__LOGIN5__V3__LOGIN_RESPONSE__RESPONSE_OK:
        snprintf(token->value, sizeof(token->value), "%s", response->ok->access_token);
        // TODO check truncation
        token->expires_after_seconds = response->ok->access_token_expires_in;
        break;
      case SPOTIFY__LOGIN5__V3__LOGIN_RESPONSE__RESPONSE_CHALLENGES:
        printf("Login %zu challenges\n", response->challenges->n_challenges);
        // TODO support hashcash challenges
        break;
      case SPOTIFY__LOGIN5__V3__LOGIN_RESPONSE__RESPONSE_ERROR:
        RETURN_ERROR(SP_ERR_LOGINFAILED, err2txt(response->error, sp_login5_error_map, ARRAY_SIZE(sp_login5_error_map)));
    }

  spotify__login5__v3__login_response__free_unpacked(response, NULL);
  return SP_OK_DONE;

 error:
  spotify__login5__v3__login_response__free_unpacked(response, NULL);
  return ret;
}

static int
handle_storage_resolve(struct sp_message *msg, struct sp_session *session)
{
  struct http_response *hres = &msg->payload.hres;
  Spotify__Download__Proto__StorageResolveResponse *response;
  struct sp_channel *channel = session->now_streaming_channel;
  int i;
  int ret;

  response = spotify__download__proto__storage_resolve_response__unpack(NULL, hres->body_len, hres->body);
  if (!response)
    RETURN_ERROR(SP_ERR_INVALID, "Could not parse storage-resolve response");

  switch (response->result)
    {
      case SPOTIFY__DOWNLOAD__PROTO__STORAGE_RESOLVE_RESPONSE__RESULT__CDN:
        for (i = 0; i < response->n_cdnurl && i < ARRAY_SIZE(channel->file.cdnurl); i++)
          channel->file.cdnurl[i] = strdup(response->cdnurl[i]);
        break;
      case SPOTIFY__DOWNLOAD__PROTO__STORAGE_RESOLVE_RESPONSE__RESULT__STORAGE:
        RETURN_ERROR(SP_ERR_INVALID, "Track not available via CDN storage");
      case SPOTIFY__DOWNLOAD__PROTO__STORAGE_RESOLVE_RESPONSE__RESULT__RESTRICTED:
        RETURN_ERROR(SP_ERR_INVALID, "Can't resolve storage, track access restricted");
    }

  spotify__download__proto__storage_resolve_response__free_unpacked(response, NULL);
  return SP_OK_DONE;

 error:
  spotify__download__proto__storage_resolve_response__free_unpacked(response, NULL);
  return ret;
}

static enum sp_error
handle_tcp_generic(struct sp_message *msg, struct sp_session *session)
{
  uint8_t *data = msg->payload.tmsg.data;
  size_t data_len = msg->payload.tmsg.len;
  enum sp_cmd_type cmd = data[0];
  uint8_t *payload = data + 3;
  size_t payload_len = data_len - 3 - 4;
  int ret;

  switch (cmd)
    {
      case CmdAPWelcome:
	ret = handle_apwelcome(payload, payload_len, session);
	break;
      case CmdAuthFailure:
	ret = handle_aplogin_failed(payload, payload_len, session);
	break;
      case CmdPing:
	ret = handle_ping(payload, payload_len, session);
	break;
      case CmdStreamChunkRes:
	ret = handle_chunk_res(payload, payload_len, session);
	break;
      case CmdCountryCode:
	memcpy(session->country, payload, sizeof(session->country) - 1);
	ret = SP_OK_OTHER;
	break;
      case CmdAesKey:
	ret = handle_aes_key(payload, payload_len, session);
	break;
      case CmdAesKeyError:
	ret = handle_aes_key_error(payload, payload_len, session);
	break;
      case CmdMercuryReq:
	ret = handle_mercury_req(payload, payload_len, session);
	break;
      case CmdChannelError:
        ret = handle_channel_error(payload, payload_len, session);
        break;
      case CmdLegacyWelcome: // 0 bytes, ignored by librespot
      case CmdSecretBlock: // ignored by librespot
      case 0x50: // XML received after login, ignored by librespot
      case CmdLicenseVersion: // ignored by librespot
      default:
	ret = SP_OK_OTHER;
    }

  return ret;
}

static enum sp_error
msg_tcp_handle(struct sp_message *msg, struct sp_session *session)
{
  struct sp_seq_request *request = session->request;

  // We have a tcp request waiting for a response
  if (request && request->proto == SP_PROTO_TCP && request->response_handler)
    {
      sp_cb.logmsg("Handling response to %s\n", request->name);
      return request->response_handler(msg, session);
    }

  sp_cb.logmsg("Handling incoming tcp message\n");
  // Not waiting for anything, could be a ping
  return handle_tcp_generic(msg, session);
}

static enum sp_error
msg_http_handle(struct sp_message *msg, struct sp_session *session)
{
  struct sp_seq_request *request = session->request;

  // We have a http request waiting for a response
  if (request && request->proto == SP_PROTO_HTTP && request->response_handler)
    {
      sp_cb.logmsg("Handling response to %s\n", request->name);
      return request->response_handler(msg, session);
    }

  sp_errmsg = "Received unexpected http response";
  return SP_ERR_INVALID;
}

// Handler must return SP_OK_DONE if the message is a response to a request.
// It must return SP_OK_OTHER if the message is something else (e.g. a ping),
// SP_ERR_xxx if the response indicates an error. Finally, SP_OK_DATA is like
// DONE except it also means that there is new audio data to write.
enum sp_error
msg_handle(struct sp_message *msg, struct sp_session *session)
{
  if (msg->type == SP_MSG_TYPE_TCP)
    return msg_tcp_handle(msg, session);
  else if (msg->type == SP_MSG_TYPE_HTTP_RES)
    return msg_http_handle(msg, session);

  sp_errmsg = "Invalid message passed to msg_handle()";
  return SP_ERR_INVALID;
}

enum sp_error
msg_tcp_read_one(struct sp_tcp_message *tmsg, struct sp_connection *conn)
{
  size_t in_len = evbuffer_get_length(conn->incoming);
  uint8_t *in = evbuffer_pullup(conn->incoming, -1);
  uint32_t be32;
  ssize_t msg_len;
  int ret;

#ifdef DEBUG_MOCK
  if (conn->is_encrypted && !conn->decrypt.key[0] && !conn->decrypt.key[1])
    {
      uint16_t be;
      memcpy(&be, in + 1, sizeof(be));
      msg_len = be16toh(be) + 7;
      if (msg_len > in_len)
	return SP_OK_WAIT;

      tmsg->data = malloc(msg_len);
      tmsg->len = msg_len;
      evbuffer_remove(conn->incoming, tmsg->data, msg_len);

      return SP_OK_DONE;
    }
#endif

  if (conn->is_encrypted)
    {
      msg_len = crypto_decrypt(in, in_len, &conn->decrypt);
      if (msg_len < 0)
	RETURN_ERROR(SP_ERR_DECRYPTION, "Decryption error");
      if (msg_len == 0)
	return SP_OK_WAIT;
    }
  else
    {
      if (in_len < sizeof(be32))
	return SP_OK_WAIT; // Wait for more data, size header is incomplete

      memcpy(&be32, in, sizeof(be32));
      msg_len = be32toh(be32);
      if (msg_len < 0)
	RETURN_ERROR(SP_ERR_INVALID, "Invalid message length");
      if (msg_len > in_len)
	return SP_OK_WAIT;

      if (!conn->handshake_completed)
	evbuffer_add(conn->handshake_packets, in, msg_len);
    }

  // At this point we have a complete, decrypted message.
  tmsg->data = malloc(msg_len);
  tmsg->len = msg_len;
  evbuffer_remove(conn->incoming, tmsg->data, msg_len);

  return SP_OK_DONE;

 error:
  return ret;
}


/* --------------------------- Outgoing messages ---------------------------- */

static int
msg_make_ap_resolve(struct sp_message *msg, struct sp_session *session)
{
  struct http_request *hreq = &msg->payload.hreq;

  hreq->url = strdup("https://apresolve.spotify.com/?type=accesspoint&type=spclient&type=dealer");
  return 0;
}

// This message is constructed like librespot does it, see handshake.rs
static int
msg_make_client_hello(struct sp_message *msg, struct sp_session *session)
{
  struct sp_tcp_message *tmsg = &msg->payload.tmsg;
  ClientHello client_hello = CLIENT_HELLO__INIT;
  BuildInfo build_info = BUILD_INFO__INIT;
  LoginCryptoHelloUnion login_crypto = LOGIN_CRYPTO_HELLO_UNION__INIT;
  LoginCryptoDiffieHellmanHello diffie_hellman = LOGIN_CRYPTO_DIFFIE_HELLMAN_HELLO__INIT;
  Cryptosuite crypto_suite = CRYPTOSUITE__CRYPTO_SUITE_SHANNON;
  uint8_t padding[1] = { 0x1e };
  uint8_t nonce[16] = { 0 };

  build_info.product = PRODUCT__PRODUCT_PARTNER;
  build_info.platform = PLATFORM__PLATFORM_LINUX_X86;
  build_info.version = 109800078;

  diffie_hellman.gc.len = sizeof(session->conn.keys.public_key);
  diffie_hellman.gc.data = session->conn.keys.public_key;
  diffie_hellman.server_keys_known = 1;

  login_crypto.diffie_hellman = &diffie_hellman;

  client_hello.build_info = &build_info;
  client_hello.n_cryptosuites_supported = 1;
  client_hello.cryptosuites_supported = &crypto_suite;
  client_hello.login_crypto_hello = &login_crypto;
  client_hello.client_nonce.len = sizeof(nonce);
  client_hello.client_nonce.data = nonce;
  client_hello.has_padding = 1;
  client_hello.padding.len = sizeof(padding);
  client_hello.padding.data = padding;

  tmsg->len = client_hello__get_packed_size(&client_hello);
  tmsg->data = malloc(tmsg->len);

  client_hello__pack(&client_hello, tmsg->data);

  tmsg->add_version_header = true;

  return 0;
}

static int
client_response_crypto(uint8_t **challenge, size_t *challenge_len, struct sp_connection *conn)
{
  uint8_t *packets;
  size_t packets_len;
  int ret;

  packets_len = evbuffer_get_length(conn->handshake_packets);
  packets = malloc(packets_len);
  evbuffer_remove(conn->handshake_packets, packets, packets_len);

  ret = crypto_challenge(challenge, challenge_len,
                         conn->encrypt.key, sizeof(conn->encrypt.key),
                         conn->decrypt.key, sizeof(conn->decrypt.key),
                         packets, packets_len,
                         conn->keys.shared_secret, conn->keys.shared_secret_len);

  free(packets);

  return ret;
}

static int
msg_make_client_response_plaintext(struct sp_message *msg, struct sp_session *session)
{
  struct sp_tcp_message *tmsg = &msg->payload.tmsg;
  ClientResponsePlaintext client_response = CLIENT_RESPONSE_PLAINTEXT__INIT;
  LoginCryptoResponseUnion login_crypto_response = LOGIN_CRYPTO_RESPONSE_UNION__INIT;
  LoginCryptoDiffieHellmanResponse diffie_hellman = LOGIN_CRYPTO_DIFFIE_HELLMAN_RESPONSE__INIT;
  uint8_t *challenge;
  size_t challenge_len;
  int ret;

  ret = client_response_crypto(&challenge, &challenge_len, &session->conn);
  if (ret < 0)
    return -1;

  diffie_hellman.hmac.len = challenge_len;
  diffie_hellman.hmac.data = challenge;

  login_crypto_response.diffie_hellman = &diffie_hellman;

  client_response.login_crypto_response = &login_crypto_response;

  tmsg->len = client_response_plaintext__get_packed_size(&client_response);
  tmsg->data = malloc(tmsg->len);

  client_response_plaintext__pack(&client_response, tmsg->data);

  free(challenge);
  return 0;
}

static int
msg_make_client_response_encrypted(struct sp_message *msg, struct sp_session *session)
{
  struct sp_tcp_message *tmsg = &msg->payload.tmsg;
  ClientResponseEncrypted client_response = CLIENT_RESPONSE_ENCRYPTED__INIT;
  LoginCredentials login_credentials = LOGIN_CREDENTIALS__INIT;
  SystemInfo system_info = SYSTEM_INFO__INIT;
  char system_information_string[64];
  char version_string[64];

  login_credentials.has_auth_data = 1;
  login_credentials.username = session->credentials.username;

  if (session->credentials.stored_cred_len > 0)
    {
      login_credentials.typ = AUTHENTICATION_TYPE__AUTHENTICATION_STORED_SPOTIFY_CREDENTIALS;
      login_credentials.auth_data.len = session->credentials.stored_cred_len;
      login_credentials.auth_data.data = session->credentials.stored_cred;
    }
  else if (session->credentials.token_len > 0)
    {
      login_credentials.typ = AUTHENTICATION_TYPE__AUTHENTICATION_SPOTIFY_TOKEN;
      login_credentials.auth_data.len = session->credentials.token_len;
      login_credentials.auth_data.data = session->credentials.token;
    }
  else if (strlen(session->credentials.password))
    {
      login_credentials.typ = AUTHENTICATION_TYPE__AUTHENTICATION_USER_PASS;
      login_credentials.auth_data.len = strlen(session->credentials.password);
      login_credentials.auth_data.data = (unsigned char *)session->credentials.password;
    }
  else
    return -1;

  snprintf(system_information_string, sizeof(system_information_string), "%s_%s_%s",
    sp_sysinfo.client_name, sp_sysinfo.client_version, sp_sysinfo.client_build_id);
  snprintf(version_string, sizeof(version_string), "%s-%s",
    sp_sysinfo.client_name, sp_sysinfo.client_version);

  system_info.cpu_family = CPU_FAMILY__CPU_UNKNOWN;
  system_info.os = OS__OS_UNKNOWN;
  system_info.system_information_string = system_information_string;
  system_info.device_id = sp_sysinfo.device_id;
  system_info_from_uname(&system_info); // Sets cpu_family and os to actual values

  client_response.login_credentials = &login_credentials;
  client_response.system_info = &system_info;
  client_response.version_string = version_string;

  tmsg->len = client_response_encrypted__get_packed_size(&client_response);
  tmsg->data = malloc(tmsg->len);

  client_response_encrypted__pack(&client_response, tmsg->data);

  tmsg->cmd = CmdLogin;
  tmsg->encrypt = true;

  return 0;
}

// From librespot-golang:
// Mercury is the protocol implementation for Spotify Connect playback control and metadata fetching. It works as a
// PUB/SUB system, where you, as an audio sink, subscribes to the events of a specified user (playlist changes) but
// also access various metadata normally fetched by external players (tracks metadata, playlists, artists, etc).
static int
msg_make_mercury_req(size_t *total_len, uint8_t *out, size_t out_len, struct sp_mercury *mercury)
{
  Header header = HEADER__INIT;
  uint8_t *ptr;
  uint16_t be;
  uint64_t be64;
  uint8_t flags = 1; // Flags "final" according to librespot
  size_t prefix_len;
  size_t header_len;
  size_t body_len;
  int i;

  prefix_len = sizeof(be) + sizeof(be64) + sizeof(flags) + sizeof(be) + sizeof(be);

  if (prefix_len > out_len)
    return -1; // Buffer too small

  ptr = out;

  be = htobe16(sizeof(be64));
  memcpy(ptr, &be, sizeof(be)); // prefix_len += sizeof(be)
  ptr += sizeof(be);

  be64 = htobe64(mercury->seq);
  memcpy(ptr, &be64, sizeof(be64)); // prefix_len += sizeof(be64)
  ptr += sizeof(be64);

  memcpy(ptr, &flags, sizeof(flags)); // prefix_len += sizeof(flags)
  ptr += sizeof(flags);

  be = htobe16(1 + mercury->parts_num); // = payload_len + 1 = "parts count"?
  memcpy(ptr, &be, sizeof(be)); // prefix_len += sizeof(be)
  ptr += sizeof(be);

  header.uri = mercury->uri;
  header.method = mercury->method; // "GET", "SUB" etc
  header.content_type = mercury->content_type;

  header_len = header__get_packed_size(&header);
  if (header_len + prefix_len > out_len)
    return -1; // Buffer too small

  be = htobe16(header_len);
  memcpy(ptr, &be, sizeof(be)); // prefix_len += sizeof(be)
  ptr += sizeof(be);

  assert(ptr - out == prefix_len);

  header__pack(&header, ptr);
  ptr += header_len;

  body_len = 0;
  for (i = 0; i < mercury->parts_num; i++)
    {
      body_len += sizeof(be) + mercury->parts[i].len;
      if (body_len + header_len + prefix_len > out_len)
	return -1; // Buffer too small

      be = htobe16(mercury->parts[i].len);
      memcpy(ptr, &be, sizeof(be));
      ptr += sizeof(be);

      memcpy(ptr, mercury->parts[i].data, mercury->parts[i].len);
      ptr += mercury->parts[i].len;
    }

  assert(ptr - out == header_len + prefix_len + body_len);

  *total_len = header_len + prefix_len + body_len;
  return 0;
}

static int
msg_make_mercury_track_get(struct sp_message *msg, struct sp_session *session)
{
  struct sp_tcp_message *tmsg = &msg->payload.tmsg;
  struct sp_mercury mercury = { 0 };
  struct sp_channel *channel = session->now_streaming_channel;
  char uri[256];
  char *ptr;
  int i;

  assert(sizeof(uri) > sizeof(SP_MERCURY_URI_TRACK) + 2 * sizeof(channel->file.media_id));

  ptr = uri;
  ptr += sprintf(ptr, "%s", SP_MERCURY_URI_TRACK);

  for (i = 0; i < sizeof(channel->file.media_id); i++)
    ptr += sprintf(ptr, "%02x", channel->file.media_id[i]);

  mercury.method = "GET";
  mercury.seq    = channel->id;
  mercury.uri    = uri;

  tmsg->data = malloc(MERCURY_REQ_SIZE_MAX);
  tmsg->cmd = CmdMercuryReq;
  tmsg->encrypt = true;

  return msg_make_mercury_req(&tmsg->len, tmsg->data, MERCURY_REQ_SIZE_MAX, &mercury);
}

static int
msg_make_mercury_episode_get(struct sp_message *msg, struct sp_session *session)
{
  struct sp_tcp_message *tmsg = &msg->payload.tmsg;
  struct sp_mercury mercury = { 0 };
  struct sp_channel *channel = session->now_streaming_channel;
  char uri[256];
  char *ptr;
  int i;

  assert(sizeof(uri) > sizeof(SP_MERCURY_URI_EPISODE) + 2 * sizeof(channel->file.media_id));

  ptr = uri;
  ptr += sprintf(ptr, "%s", SP_MERCURY_URI_EPISODE);

  for (i = 0; i < sizeof(channel->file.media_id); i++)
    ptr += sprintf(ptr, "%02x", channel->file.media_id[i]);

  mercury.method = "GET";
  mercury.seq    = channel->id;
  mercury.uri    = uri;

  tmsg->data = malloc(MERCURY_REQ_SIZE_MAX);
  tmsg->cmd = CmdMercuryReq;
  tmsg->encrypt = true;

  return msg_make_mercury_req(&tmsg->len, tmsg->data, MERCURY_REQ_SIZE_MAX, &mercury);
}

static int
msg_make_audio_key_get(struct sp_message *msg, struct sp_session *session)
{
  struct sp_tcp_message *tmsg = &msg->payload.tmsg;
  struct sp_channel *channel = session->now_streaming_channel;
  uint8_t *ptr;
  uint32_t be32;
  uint16_t be;

  tmsg->len = sizeof(channel->file.id) + sizeof(channel->file.media_id) + sizeof(be32) + sizeof(be);
  tmsg->data = malloc(tmsg->len);

  ptr = tmsg->data;

  memcpy(ptr, channel->file.id, sizeof(channel->file.id));
  ptr += sizeof(channel->file.id);

  memcpy(ptr, channel->file.media_id, sizeof(channel->file.media_id));
  ptr += sizeof(channel->file.media_id);

  be32 = htobe32(channel->id);
  memcpy(ptr, &be32, sizeof(be32));
  ptr += sizeof(be32);

  be = htobe16(0); // Unknown
  memcpy(ptr, &be, sizeof(be));
  ptr += sizeof(be);

  tmsg->cmd = CmdRequestKey;
  tmsg->encrypt = true;

  return 0;
}

static int
msg_make_chunk_request(struct sp_message *msg, struct sp_session *session)
{
  struct sp_tcp_message *tmsg = &msg->payload.tmsg;
  struct sp_channel *channel = session->now_streaming_channel;
  uint8_t *ptr;
  uint16_t be;
  uint32_t be32;

  if (!channel)
    return -1;

  tmsg->len = 3 * sizeof(be) + sizeof(channel->file.id) + 5 * sizeof(be32);
  tmsg->data = malloc(tmsg->len);

  ptr = tmsg->data;

  be = htobe16(channel->id);
  memcpy(ptr, &be, sizeof(be));
  ptr += sizeof(be); // x1

  be = htobe16(1); // Unknown purpose
  memcpy(ptr, &be, sizeof(be));
  ptr += sizeof(be); // x2

  be = htobe16(0); // Unknown purpose
  memcpy(ptr, &be, sizeof(be));
  ptr += sizeof(be); // x3

  be32 = htobe32(0); // Unknown purpose
  memcpy(ptr, &be32, sizeof(be32));
  ptr += sizeof(be32); // x1

  be32 = htobe32(0x00009C40); // Unknown purpose
  memcpy(ptr, &be32, sizeof(be32));
  ptr += sizeof(be32); // x2

  be32 = htobe32(0x00020000); // Unknown purpose
  memcpy(ptr, &be32, sizeof(be32));
  ptr += sizeof(be32); // x3

  memcpy(ptr, channel->file.id, sizeof(channel->file.id));
  ptr += sizeof(channel->file.id);

  be32 = htobe32(channel->file.offset_words);
  memcpy(ptr, &be32, sizeof(be32));
  ptr += sizeof(be32); // x4

  be32 = htobe32(channel->file.offset_words + SP_CHUNK_LEN_WORDS);
  memcpy(ptr, &be32, sizeof(be32));
  ptr += sizeof(be32); // x5

  assert(tmsg->len == ptr - tmsg->data);
  assert(tmsg->len == 46);

  tmsg->cmd = CmdStreamChunk;
  tmsg->encrypt = true;

  return 0;
}

static int
msg_make_pong(struct sp_message *msg, struct sp_session *session)
{
  struct sp_tcp_message *tmsg = &msg->payload.tmsg;

  tmsg->len = 4;
  tmsg->data = calloc(1, tmsg->len); // librespot just replies with zeroes

  tmsg->cmd = CmdPong;
  tmsg->encrypt = true;

  return 0;
}

// Ref. session/clienttoken.go
static int
msg_make_clienttoken(struct sp_message *msg, struct sp_session *session)
{
  struct http_request *hreq = &msg->payload.hreq;
  Spotify__Clienttoken__Http__V0__ClientTokenRequest treq = SPOTIFY__CLIENTTOKEN__HTTP__V0__CLIENT_TOKEN_REQUEST__INIT;
  Spotify__Clienttoken__Http__V0__ClientDataRequest dreq = SPOTIFY__CLIENTTOKEN__HTTP__V0__CLIENT_DATA_REQUEST__INIT;
  Spotify__Clienttoken__Data__V0__ConnectivitySdkData sdk_data = SPOTIFY__CLIENTTOKEN__DATA__V0__CONNECTIVITY_SDK_DATA__INIT;
  Spotify__Clienttoken__Data__V0__PlatformSpecificData platform_data = SPOTIFY__CLIENTTOKEN__DATA__V0__PLATFORM_SPECIFIC_DATA__INIT;

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
  sdk_data.device_id = sp_sysinfo.device_id; // e.g. "bcbae1f3062baac486045f13935c6c95ad4191ff"

  dreq.connectivity_sdk_data = &sdk_data;
  dreq.data_case = SPOTIFY__CLIENTTOKEN__HTTP__V0__CLIENT_DATA_REQUEST__DATA_CONNECTIVITY_SDK_DATA;
  dreq.client_version = sp_sysinfo.client_version; // e.g. "0.0.0" (SpotifyLikeClient)
  dreq.client_id = SP_CLIENT_ID_HEX;

  treq.client_data = &dreq;
  treq.request_type = SPOTIFY__CLIENTTOKEN__HTTP__V0__CLIENT_TOKEN_REQUEST_TYPE__REQUEST_CLIENT_DATA_REQUEST;
  treq.request_case = SPOTIFY__CLIENTTOKEN__HTTP__V0__CLIENT_TOKEN_REQUEST__REQUEST_CLIENT_DATA;

  hreq->body_len = spotify__clienttoken__http__v0__client_token_request__get_packed_size(&treq);
  hreq->body = malloc(hreq->body_len);

  spotify__clienttoken__http__v0__client_token_request__pack(&treq, hreq->body);

  hreq->url = strdup("https://clienttoken.spotify.com/v1/clienttoken");

  hreq->headers[0] = strdup("Accept: application/x-protobuf");
  hreq->headers[1] = strdup("Content-Type: application/x-protobuf");

  return 0;
}

// Ref. login5/login5.go
static int
msg_make_login5(struct sp_message *msg, struct sp_session *session)
{
  struct http_request *hreq = &msg->payload.hreq;
  Spotify__Login5__V3__LoginRequest req = SPOTIFY__LOGIN5__V3__LOGIN_REQUEST__INIT;
  Spotify__Login5__V3__ClientInfo client_info = SPOTIFY__LOGIN5__V3__CLIENT_INFO__INIT;
  Spotify__Login5__V3__Credentials__StoredCredential stored_credential = SPOTIFY__LOGIN5__V3__CREDENTIALS__STORED_CREDENTIAL__INIT;

  if (session->credentials.stored_cred_len == 0)
    return -1;

  client_info.client_id = SP_CLIENT_ID_HEX;
  client_info.device_id = sp_sysinfo.device_id;

  req.client_info = &client_info;

  stored_credential.username = session->credentials.username;
  stored_credential.data.data = session->credentials.stored_cred;
  stored_credential.data.len = session->credentials.stored_cred_len;

  req.login_method_case = SPOTIFY__LOGIN5__V3__LOGIN_REQUEST__LOGIN_METHOD_STORED_CREDENTIAL;
  req.stored_credential = &stored_credential;

  hreq->body_len = spotify__login5__v3__login_request__get_packed_size(&req);
  hreq->body = malloc(hreq->body_len);

  spotify__login5__v3__login_request__pack(&req, hreq->body);

  hreq->url = strdup("https://login5.spotify.com/v3/login");

  hreq->headers[0] = asprintf_or_die("Accept: application/x-protobuf");
  hreq->headers[1] = asprintf_or_die("Content-Type: application/x-protobuf");
  hreq->headers[2] = asprintf_or_die("Client-Token: %s", session->http_clienttoken.value);

  return 0;
}

// Resolve storage, this will just be a GET request
// Ref. spclient/spclient.go
static int
msg_make_storage_resolve_track(struct sp_message *msg, struct sp_session *session)
{
  struct http_request *hreq = &msg->payload.hreq;
  struct sp_server *server = &session->spclient;
  struct sp_channel *channel = session->now_streaming_channel;
  char *track_id = NULL;
  char *ptr;
  int i;

  track_id = malloc(2 * sizeof(channel->file.id) + 1);
  for (i = 0, ptr = track_id; i < sizeof(channel->file.id); i++)
    ptr += sprintf(ptr, "%02x", channel->file.id[i]);

  hreq->url = asprintf_or_die("https://%s:%d/storage-resolve/files/audio/interactive/%s", server->address, server->port, track_id);

  hreq->headers[0] = asprintf_or_die("Accept: application/x-protobuf");
  hreq->headers[1] = asprintf_or_die("Client-Token: %s", session->http_clienttoken.value);
  hreq->headers[2] = asprintf_or_die("Authorization: Bearer %s", session->http_accesstoken.value);

  free(track_id);
  return 0;
}

/*
bool
msg_is_handshake(enum sp_msg_type type)
{
  return ( type == MSG_TYPE_CLIENT_HELLO ||
           type == MSG_TYPE_CLIENT_RESPONSE_PLAINTEXT ||
           type == MSG_TYPE_CLIENT_RESPONSE_ENCRYPTED );
}
*/

// Must be large enough to also include null terminating elements
static struct sp_seq_request seq_requests[][7] =
{
/*
  {
    { SP_SEQ_CONNECT, "AP_RESOLVE", SP_PROTO_HTTP, msg_make_ap_resolve, response_ap_resolve, },
  },*/
  {
    { SP_SEQ_LOGIN, "AP_RESOLVE", SP_PROTO_HTTP, msg_make_ap_resolve, NULL, handle_ap_resolve, },
    { SP_SEQ_LOGIN, "CLIENT_HELLO", SP_PROTO_TCP, msg_make_client_hello, prepare_tcp, handle_client_hello, },
    { SP_SEQ_LOGIN, "CLIENT_RESPONSE_PLAINTEXT", SP_PROTO_TCP, msg_make_client_response_plaintext, prepare_tcp, NULL, },
    { SP_SEQ_LOGIN, "CLIENT_RESPONSE_ENCRYPTED", SP_PROTO_TCP,  msg_make_client_response_encrypted, prepare_tcp, handle_tcp_generic, },
    { SP_SEQ_LOGIN, "CLIENTTOKEN", SP_PROTO_HTTP, msg_make_clienttoken, NULL, handle_clienttoken, },
    { SP_SEQ_LOGIN, "LOGIN5", SP_PROTO_HTTP, msg_make_login5, prepare_http_auth, handle_login5, },
  },
  {
    { SP_SEQ_TRACK_OPEN, "MERCURY_TRACK_GET", SP_PROTO_TCP, msg_make_mercury_track_get, prepare_tcp, handle_tcp_generic, },
    { SP_SEQ_TRACK_OPEN, "AUDIO_KEY_GET", SP_PROTO_TCP, msg_make_audio_key_get, prepare_tcp, handle_tcp_generic, },
    { SP_SEQ_TRACK_OPEN, "STORAGE_RESOLVE", SP_PROTO_HTTP, msg_make_storage_resolve_track, prepare_http_auth, handle_storage_resolve, },
  },
  {
    { SP_SEQ_EPISODE_OPEN, "MERCURY_EPISODE_GET", SP_PROTO_TCP, msg_make_mercury_episode_get, prepare_tcp, handle_tcp_generic, },
    { SP_SEQ_EPISODE_OPEN, "AUDIO_KEY_GET", SP_PROTO_TCP, msg_make_audio_key_get, prepare_tcp, handle_tcp_generic, },
  },
  {
    { SP_SEQ_MEDIA_GET, "CHUNK_REQUEST", SP_PROTO_TCP, msg_make_chunk_request, prepare_tcp, handle_tcp_generic, },
  },
  {
// TODO
    { SP_SEQ_MEDIA_SEEK, "CHUNK_SEEK", SP_PROTO_TCP, msg_make_chunk_request, prepare_tcp, handle_tcp_generic, },
  },
  {
    { SP_SEQ_PONG, "PONG", SP_PROTO_TCP, msg_make_pong, prepare_tcp, NULL, },
  },
};

int
seq_requests_check(void)
{
  for (int i = 0; i < ARRAY_SIZE(seq_requests); i++)
    {
      if (i != seq_requests[i]->seq_type)
	return -1;
    }

  return 0;
}

struct sp_seq_request *
seq_request_get(enum sp_seq_type seq_type, int n)
{
  return &seq_requests[seq_type][n];
}

enum sp_error
seq_request_prepare(struct sp_seq_request *request, struct sp_conn_callbacks *cb, struct sp_session *session)
{
  if (!request->request_prepare)
    return SP_OK_DONE;

  return request->request_prepare(request, cb, session);
}

void
msg_clear(struct sp_message *msg)
{
  if (!msg)
    return;

  if (msg->type == SP_MSG_TYPE_HTTP_REQ)
    http_request_free(&msg->payload.hreq, true);
  else if (msg->type == SP_MSG_TYPE_HTTP_RES)
    http_response_free(&msg->payload.hres, true);
  else if (msg->type == SP_MSG_TYPE_TCP)
    free(msg->payload.tmsg.data);

  memset(msg, 0, sizeof(struct sp_message));
}

int
msg_make(struct sp_message *msg, struct sp_seq_request *req, struct sp_session *session)
{
  memset(msg, 0, sizeof(struct sp_message));

  msg->type = (req->proto == SP_PROTO_HTTP) ? SP_MSG_TYPE_HTTP_REQ : SP_MSG_TYPE_TCP;

  return req->payload_make(msg, session);
}

/*
  switch (type)
    {
      case MSG_TYPE_CLIENT_HELLO:
	msg->len = msg_make_client_hello(msg->data, sizeof(msg->data), session);
	msg->type_next = MSG_TYPE_CLIENT_RESPONSE_PLAINTEXT;
	msg->add_version_header = true;
	msg->response_handler = response_client_hello;
	break;
      case MSG_TYPE_CLIENT_RESPONSE_PLAINTEXT:
	msg->len = msg_make_client_response_plaintext(msg->data, sizeof(msg->data), session);
	msg->type_next = MSG_TYPE_CLIENT_RESPONSE_ENCRYPTED;
	msg->response_handler = NULL; // No response expected
	break;
      case MSG_TYPE_CLIENT_RESPONSE_ENCRYPTED:
	msg->len = msg_make_client_response_encrypted(msg->data, sizeof(msg->data), session);
	msg->type_next = MSG_TYPE_HTTP_CLIENTTOKEN;
	msg->cmd = CmdLogin;
        msg->encrypt = true;
	msg->response_handler = response_generic;
	break;
      case MSG_TYPE_HTTP_CLIENTTOKEN:
	msg->len = msg_make_clienttoken(msg->data, sizeof(msg->data), session);
	msg->url = "https://clienttoken.spotify.com/v1/clienttoken";
	msg->type_next = MSG_TYPE_HTTP_LOGIN5;
	msg->response_handler = response_clienttoken;
	msg->is_http = true;
	break;
      case MSG_TYPE_HTTP_LOGIN5:
	msg->len = msg_make_login5(msg->data, sizeof(msg->data), session);
	msg->url = "https://login5.spotify.com/v3/login";
	msg->header[0] = clienttoken;
	msg->response_handler = response_login5;
	msg->is_http = true;
	break;
      case MSG_TYPE_MERCURY_TRACK_GET:
	msg->len = msg_make_mercury_track_get(msg->data, sizeof(msg->data), session);
	msg->cmd = CmdMercuryReq;
        msg->encrypt = true;
	msg->type_next = MSG_TYPE_AUDIO_KEY_GET;
	msg->response_handler = response_generic;
	break;
      case MSG_TYPE_MERCURY_EPISODE_GET:
	msg->len = msg_make_mercury_episode_get(msg->data, sizeof(msg->data), session);
	msg->cmd = CmdMercuryReq;
        msg->encrypt = true;
	msg->type_next = MSG_TYPE_AUDIO_KEY_GET;
	msg->response_handler = response_generic;
	break;
      case MSG_TYPE_AUDIO_KEY_GET:
	msg->len = msg_make_audio_key_get(msg->data, sizeof(msg->data), session);
	msg->cmd = CmdRequestKey;
        msg->encrypt = true;
	msg->type_next = MSG_TYPE_CHUNK_REQUEST;
	msg->response_handler = response_generic;
	break;
      case MSG_TYPE_CHUNK_REQUEST:
	msg->len = msg_make_chunk_request(msg->data, sizeof(msg->data), session);
	msg->cmd = CmdStreamChunk;
        msg->encrypt = true;
	msg->response_handler = response_generic;
	break;
      case MSG_TYPE_PONG:
	msg->len = 4;
	msg->cmd = CmdPong;
        msg->encrypt = true;
	memset(msg->data, 0, msg->len); // librespot just replies with zeroes
	break;
      default:
	msg->len = -1;
    }

  return (msg->len < 0) ? -1 : 0;
}
*/

enum sp_error
msg_tcp_send(struct sp_tcp_message *tmsg, struct sp_connection *conn)
{
  uint8_t pkt[4096];
  ssize_t pkt_len;
  int ret;

  if (conn->is_encrypted)
    pkt_len = packet_make_encrypted(pkt, sizeof(pkt), tmsg->cmd, tmsg->data, tmsg->len, &conn->encrypt);
  else
    pkt_len = packet_make_plain(pkt, sizeof(pkt), tmsg->data, tmsg->len, tmsg->add_version_header);

  if (pkt_len < 0)
    RETURN_ERROR(SP_ERR_INVALID, "Error constructing packet to Spotify");

#ifndef DEBUG_MOCK
  ret = send(conn->response_fd, pkt, pkt_len, 0);
  if (ret != pkt_len)
    RETURN_ERROR(SP_ERR_NOCONNECTION, "Error sending packet to Spotify");

//  sp_cb.logmsg("Sent pkt type %d (cmd=0x%02x) with size %zu (fd=%d)\n", tmsg->type, tmsg->cmd, pkt_len, conn->response_fd);
#else
  ret = debug_mock_response(msg, conn);
  if (ret < 0)
    RETURN_ERROR(SP_ERR_NOCONNECTION, "Error mocking send packet to Spotify");

  sp_cb.logmsg("Mocked send/response pkt type %d (cmd=0x%02x) with size %zu\n", tmsg->type, tmsg->cmd, pkt_len);
#endif

  // Save sent packet for MAC calculation later
  if (!conn->handshake_completed)
    evbuffer_add(conn->handshake_packets, pkt, pkt_len);

  // Reset the disconnect timer
  event_add(conn->idle_ev, &sp_idle_tv);

  return SP_OK_DONE;

 error:
  return ret;
}

enum sp_error
msg_http_send(struct http_response *hres, struct http_request *hreq)
{
  int ret;

  hreq->user_agent = sp_sysinfo.client_name;

  sp_cb.logmsg("Making http request to %s\n", hreq->url);

  ret = http_request(hres, hreq, NULL);
  if (ret < 0)
    RETURN_ERROR(SP_ERR_NOCONNECTION, "No connection to Spotify for http request");
  if (hres->code != 200) // TODO expected return code should be part of msg
    RETURN_ERROR(SP_ERR_INVALID, "Request to Spotify returned an error");

  return SP_OK_DONE;

 error:
  return ret;
}

enum sp_error
msg_pong(struct sp_session *session)
{
  struct sp_seq_request *req;
  struct sp_message msg = { 0 };
  int ret;

  req = seq_request_get(SP_SEQ_PONG, 0);

  ret = msg_make(&msg, req, session);
  if (ret < 0)
    RETURN_ERROR(SP_ERR_INVALID, "Error constructing pong message to Spotify");

  ret = msg_tcp_send(&msg.payload.tmsg, &session->conn);
  if (ret < 0)
    RETURN_ERROR(ret, sp_errmsg);

  msg_clear(&msg);

  return SP_OK_DONE;

 error:
  msg_clear(&msg);

  return ret;
}

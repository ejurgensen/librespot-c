#include <json-c/json.h>

#include "librespot-c-internal.h"
#include "http.h"

#define SP_AP_RESOLVE_URL "https://apresolve.spotify.com/?type=accesspoint&type=spclient&type=dealer"
#define SP_AP_RESOLVE_ACCESSPOINT_KEY "accesspoint"
#define SP_AP_RESOLVE_SPCLIENT_KEY "spclient"
#define SP_AP_RESOLVE_DEALER_KEY "dealer"
#define SP_AP_RESOLVE_AVOID_SECS 3600

static int
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
  return 0;

 error:
  return ret;
}

// Connects to access point resolver and selects the first access point unless
// it has recently failed
int
apresolve_server_get(struct sp_server *accesspoint, struct sp_server *spclient, struct sp_server *dealer)
{
  char *body = NULL;
  json_object *jresponse = NULL;
  int ret;

  ret = http_get(&body, SP_AP_RESOLVE_URL);
  if (ret < 0)
    RETURN_ERROR(SP_ERR_NOCONNECTION, "Could not connect to access point resolver");

  jresponse = json_tokener_parse(body);
  if (!jresponse)
    RETURN_ERROR(SP_ERR_NOCONNECTION, "Could not parse reply from access point resolver");

  ret = resolve_server_info_set(accesspoint, SP_AP_RESOLVE_ACCESSPOINT_KEY, jresponse);
  if (ret < 0)
    goto error;

  ret = resolve_server_info_set(spclient, SP_AP_RESOLVE_SPCLIENT_KEY, jresponse);
  if (ret < 0)
    goto error;

  ret = resolve_server_info_set(dealer, SP_AP_RESOLVE_DEALER_KEY, jresponse);
  if (ret < 0)
    goto error;

  json_object_put(jresponse);
  free(body);
  return 0;

 error:
  json_object_put(jresponse);
  free(body);
  return ret;
}

void
apresolve_server_mark_failed(struct sp_server *server)
{
  server->last_failed_ts = time(NULL);
}

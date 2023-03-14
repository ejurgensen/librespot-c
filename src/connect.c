/*
 * The MIT License (MIT)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <event2/buffer.h>
#include <event2/http.h>
#include <event2/keyvalq_struct.h>
#include <json-c/json.h>

#include "librespot-c-internal.h"
#include "connection.h"
#include "channel.h"

/*
 * Overview of Spotify Connect sequence w/o blob auth
 *
 * 1. Log in to AP
 * 2. Send a Spotify Connect hello() - spirc
 * 3. Reply to action=getInfo from the Spotify app
 *
 */


// See https://developer.spotify.com/documentation/commercial-hardware/implementation/guides/zeroconf/

#define STATUS_OK               101 // OK Successful operation
#define STATUS_BAD              102 // ERROR-BAD-REQUEST Web server problem or critically malformed request
#define STATUS_UNKNOWN          103 // ERROR-UNKNOWN Fallback when no other error applies.
#define STATUS_NOTIMPLEMENTED   104 // ERROR-NOT-IMPLEMENTED Server does not implement this feature
#define STATUS_LOGINFAILED      202 // ERROR-LOGIN-FAILED Spotify returned error when trying to login
#define STATUS_MISSINGACTION    301 // ERROR-MISSING-ACTION Web request has no action parameter
#define STATUS_INVALIDACTION    302 // ERROR-INVALID-ACTION Web request has unrecognized action parameter
#define STATUS_INVALIDARGUMENTS 303 // ERROR-INVALID-ARGUMENTS Incorrect or insufficient arguments supplied for requested action
#define STATUS_SPOTIFYERROR     402 // ERROR-SPOTIFY-ERROR A Spotify API call returned an error not covered by other error messages

static void
jstr_add(json_object *obj, const char *key, const char *value)
{
  if (!value)
    return;

  json_object_object_add(obj, key, json_object_new_string(value));
}

static void
jint_add(json_object *obj, const char *key, int value)
{
  json_object_object_add(obj, key, json_object_new_int(value));
}

static void
jparse_free(json_object* obj)
{
  if (!obj)
    return;

  json_object_put(obj);
}

static int
response_make(uint8_t **response, size_t *len, json_object *jreply)
{
  const char *reply;
  int ret;

  reply = json_object_to_json_string(jreply);
  if (!reply)
    RETURN_ERROR(SP_ERR_INVALID, "Could not create JSON string");

  *len = strlen(reply);
  *response = strdup(reply);
  if (!*response)
    RETURN_ERROR(SP_ERR_OOM, "Out of memory");

  return 0;

 error:
  return ret;
}

int
librespotc_connect_getinfo(uint8_t **response, size_t *len, struct sp_sysinfo *info, struct sp_credentials *credentials)
{
#define DUMMY_KEY "cOoqpxJrMI2feE8GBnkSGIp4fDM3ZI+dfWcrX/mjoUxJr1I56C+tS1tu1/VpRclRjbuwlu47LCeY7cC6Ol+ScALHd8S1hoUgKLaM7nYFted488DAHCEXUPMAc6qWObfc"
  json_object *jreply;
  int ret;

  jreply = json_object_new_object();
  if (!jreply)
    RETURN_ERROR(SP_ERR_OOM, "Out of memory");

  jint_add(jreply, "status", STATUS_OK);
  jstr_add(jreply, "statusString", "OK");
  jint_add(jreply, "spotifyError", 0);

  jstr_add(jreply, "version", "2.9.0");
  jstr_add(jreply, "deviceID", info->device_id);
  jstr_add(jreply, "deviceType", "SPEAKER");
  jstr_add(jreply, "remoteName", info->speaker_name);

  jstr_add(jreply, "publicKey", DUMMY_KEY); // We aren't doing blob-based auth so don't need a real key
  jstr_add(jreply, "brandDisplayName", info->client_name);
  jstr_add(jreply, "modelDisplayName", info->client_name);
  jstr_add(jreply, "libraryVersion", info->client_version);
  jstr_add(jreply, "resolverVersion", "1");
  jstr_add(jreply, "groupStatus", "NONE");
  jstr_add(jreply, "tokenType", "default"); // Spotify example uses "accesstoken"
  jstr_add(jreply, "clientID", info->client_build_id);
  jint_add(jreply, "productID", 0);
  jstr_add(jreply, "scope", "streaming"); // Other known scope: client-authorization-universal
  jstr_add(jreply, "availability", "");
//  jarr_add(jreply, "supported_drm_media_formats", []); // Not required
  jint_add(jreply, "supported_capabilities", 1);
  jstr_add(jreply, "accountReq", "PREMIUM"); // undocumented but should still work
  jstr_add(jreply, "activeUser", credentials->username);

  ret = response_make(response, len, jreply);
  if (ret < 0)
    goto error;

  jparse_free(jreply);
  return 0;

 error:
  jparse_free(jreply);
  return ret;
#undef DUMMY_KEY
}

static int
make_response_adduser(uint8_t **response, size_t *len, char *body, struct sp_credentials *credentials)
{
  json_object *jreply;
  struct evkeyvalq query = { 0 };
  const char *param;
  int ret;

  jreply = json_object_new_object();
  if (!jreply)
    RETURN_ERROR(SP_ERR_OOM, "Out of memory");

  ret = evhttp_parse_query_str(body, &query);
  if (ret < 0)
    RETURN_ERROR(SP_ERR_INVALID, "Spotify Connect unreadable POST request");

  param = evhttp_find_header(&query, "action");
  if (!param || strcmp(param, "addUser") != 0)
    RETURN_ERROR(SP_ERR_INVALID, "Spotify Connect unexpected POST request");

  param = evhttp_find_header(&query, "userName");
  if (!param || strcmp(param, credentials->username) != 0)
    RETURN_ERROR(SP_ERR_OCCUPIED, "Spotify Connect connecting attempt from user not logged in");

  jint_add(jreply, "status", STATUS_OK);
  jstr_add(jreply, "statusString", "OK");
  jint_add(jreply, "spotifyError", 0);

  ret = response_make(response, len, jreply);
  if (ret < 0)
    goto error;

  evhttp_clear_headers(&query);
  jparse_free(jreply);
  return 0;

 error:
  evhttp_clear_headers(&query);
  jparse_free(jreply);
  return ret;
}

int
librespotc_connect_adduser(uint8_t **response, size_t *len, char *body, struct sp_session *session)
{
  struct sp_message msg;
  int ret;

  ret = make_response_adduser(response, len, body, &session->credentials);
  if (ret < 0)
    RETURN_ERROR(ret, sp_errmsg);

  RETURN_ERROR(SP_ERR_INVALID, "Spotify Connect adduser not implemented");

  return 0;

 error:
  return ret;
}

int
librespotc_connect_hello(struct sp_session *session)
{
  struct sp_message msg;
  int ret;

  ret = msg_make(&msg, MSG_TYPE_SPIRC_HELLO, session);
  if (ret < 0)
    RETURN_ERROR(SP_ERR_INVALID, "Error constructing Spirc hello to Spotify");


  ret = msg_send(&msg, &session->conn);
  if (ret < 0)
    RETURN_ERROR(ret, sp_errmsg);

  return 0;

 error:
  return ret;
}

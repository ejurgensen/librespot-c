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

#include <event2/buffer.h>
#include <json-c/json.h>

#include "librespot-c-internal.h"

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

/*
static json_object *
jparse_obj_from_evbuffer(struct evbuffer *evbuf)
{
  char *json_str;

  // 0-terminate for safety
  evbuffer_add(evbuf, "", 1);

  json_str = (char *) evbuffer_pullup(evbuf, -1);
  if (!json_str || (strlen(json_str) == 0))
    return NULL;

  return json_tokener_parse(json_str);
}
*/

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

int
librespotc_connect_getinfo(uint8_t **response, size_t *len, struct sp_sysinfo *info, struct sp_credentials *credentials)
{
  json_object *jreply;
  const char *reply;
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

  jstr_add(jreply, "publicKey", "123"); // TODO
  jstr_add(jreply, "brandDisplayName", info->client_name);
  jstr_add(jreply, "modelDisplayName", info->client_name);
  jstr_add(jreply, "libraryVersion", info->client_version);
  jstr_add(jreply, "resolverVersion", "1");
  jstr_add(jreply, "groupStatus", "NONE");
  jstr_add(jreply, "tokenType", "default");
  jstr_add(jreply, "clientID", info->client_build_id);
  jint_add(jreply, "productID", 0);
  jstr_add(jreply, "scope", "streaming"); // Other known scope: client-authorization-universal
  jstr_add(jreply, "availability", "");
//  jarr_add(jreply, "supported_drm_media_formats", []); // Not required
  jint_add(jreply, "supported_capabilities", 1);
  jstr_add(jreply, "accountReq", "PREMIUM"); // undocumented but should still work
  jstr_add(jreply, "activeUser", credentials->username);

  reply = json_object_to_json_string(jreply);
  if (!reply)
    RETURN_ERROR(SP_ERR_INVALID, "Could not create JSON string");

  *len = strlen(reply);
  *response = strdup(reply);
  if (!*response)
    RETURN_ERROR(SP_ERR_OOM, "Out of memory");

  jparse_free(jreply);

  return 0;

 error:
  return ret;
}

/*
int
connect_discover_handle_adduser(struct evbuffer *out, struct evbuffer *in)
{
  json_object *haystack;

  haystack = jparse_obj_from_evbuffer(in);
}
*/

#ifndef __HTTP_H__
#define __HTTP_H__

#include <stdbool.h>
#include <stdint.h>

#define HTTP_MAX_HEADERS 32

struct http_session;

struct http_request
{
  const char *url;

  const char *user_agent;
  bool headers_only; // HEAD request
  bool ssl_verify_peer;

  const char *headers[HTTP_MAX_HEADERS];
  uint8_t *body; // If not NULL and body_len > 0 -> POST request
  size_t body_len;
};

struct http_response
{
  struct http_request *request;

  int code;
  ssize_t content_length; // -1 = unknown

  char *headers[HTTP_MAX_HEADERS];
  uint8_t *body; // Allocated, must be freed by caller
  size_t body_len;
};

void
http_session_init(struct http_session *session);

void
http_session_deinit(struct http_session *session);

// A sync request. The session is optional but increases performance when
// making many requests.
int
http_request(struct http_response *res, struct http_request *req, struct http_session *session);

// Wraps around http_request() for a simple GET request
int
http_get(char **body, const char *url);

#endif /* !__HTTP_H__ */

#ifndef __HTTP_H__
#define __HTTP_H__

#include <stdbool.h>
#include <stdint.h>

#define HTTP_MAX_HEADERS 32

struct http_session;

struct http_request
{
  char *url;

  const char *user_agent;
  bool headers_only; // HEAD request
  bool ssl_verify_peer;

  char *headers[HTTP_MAX_HEADERS];
  uint8_t *body; // If not NULL and body_len > 0 -> POST request
  size_t body_len;
};

struct http_response
{
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

void
http_request_free(struct http_request *req, bool only_content);

void
http_response_free(struct http_response *res, bool only_content);

// The session is optional but increases performance when making many requests.
int
http_request(struct http_response *response, struct http_request *request, struct http_session *session);

#endif /* !__HTTP_H__ */

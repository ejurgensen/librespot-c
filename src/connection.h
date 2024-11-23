void
ap_disconnect(struct sp_connection *conn);

enum sp_error
ap_connect(struct sp_connection *conn, struct sp_server *server, time_t *cooldown_ts, struct sp_conn_callbacks *cb, void *cb_arg);

int
seq_requests_check(void);

struct sp_seq_request *
seq_request_get(enum sp_seq_type seq_type, int n);

enum sp_error
seq_request_prepare(struct sp_seq_request *request, struct sp_conn_callbacks *cb, struct sp_session *session);

enum sp_error
msg_tcp_read_one(struct sp_tcp_message *tmsg, struct sp_connection *conn);

enum sp_error
msg_handle(struct sp_message *msg, struct sp_session *session);

void
msg_clear(struct sp_message *msg);

int
msg_make(struct sp_message *msg, struct sp_seq_request *req, struct sp_session *session);

enum sp_error
msg_tcp_send(struct sp_tcp_message *tmsg, struct sp_connection *conn);

enum sp_error
msg_http_send(struct http_response *hres, struct http_request *hreq);

int
msg_pong(struct sp_session *session);

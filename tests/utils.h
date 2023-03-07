void
hexdump(const char *msg, uint8_t *mem, size_t len);

void
logmsg(const char *fmt, ...);

int
https_get(char **body, const char *url);

int
tcp_connect(const char *address, unsigned short port);

void
tcp_disconnect(int fd);

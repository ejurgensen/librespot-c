
#ifndef __MDNS_H__
#define __MDNS_H__

int
mdns_init(struct event_base *evbase);

void
mdns_deinit(void);

int
mdns_register(char *name, char *type, int port, char **txt);

#endif /* !__MDNS_H__ */

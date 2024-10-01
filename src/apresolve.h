// Connects to access point resolver and for each server type selects the first
// unless it has recently failed
int
apresolve_server_get(struct sp_server *accesspoint, struct sp_server *spclient, struct sp_server *dealer);

void
apresolve_server_mark_failed(struct sp_server *server);

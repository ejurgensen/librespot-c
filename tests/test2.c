#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h> // for isprint()

#include "librespot-c.h"

static void
hexdump(const char *msg, uint8_t *mem, size_t len)
{
  int i, j;
  int hexdump_cols = 16;

  if (msg)
    printf("%s", msg);

  for (i = 0; i < len + ((len % hexdump_cols) ? (hexdump_cols - len % hexdump_cols) : 0); i++)
    {
      if(i % hexdump_cols == 0)
	printf("0x%06x: ", i);

      if (i < len)
	printf("%02x ", 0xFF & ((char*)mem)[i]);
      else
	printf("   ");

      if (i % hexdump_cols == (hexdump_cols - 1))
	{
	  for (j = i - (hexdump_cols - 1); j <= i; j++)
	    {
	      if (j >= len)
		putchar(' ');
	      else if (isprint(((char*)mem)[j]))
		putchar(0xFF & ((char*)mem)[j]);
	      else
		putchar('.');
	    }

	  putchar('\n');
	}
    }
}

static void
logmsg(const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  vprintf(fmt, ap);
  va_end(ap);
}

struct sp_callbacks callbacks =
{
/*
  .https_get = https_get,
  .tcp_connect = tcp_connect,
  .tcp_disconnect = tcp_disconnect,
*/
  .thread_name_set = NULL,

  .hexdump  = hexdump,
  .logmsg   = logmsg,
};

int
main(int argc, char * argv[])
{
//  struct sp_session *session = NULL;
  struct sp_sysinfo sysinfo = { 0 };
//  struct sp_credentials credentials;
//  struct sp_metadata metadata;
//  struct event *read_ev;
  FILE *f_stored_cred = NULL;
  uint8_t stored_cred[256];
  size_t stored_cred_len;
//  struct event *stop_ev;
//  struct timeval tv = { 0 };
  int ret;

  if (argc != 4)
    {
      printf("%s spotify_path username stored_credentials_file\n", argv[0]);
      goto error;
    }

  snprintf(sysinfo.device_id, sizeof(sysinfo.device_id), "622682995d5c1db29722de8dd85f6c3acd6fc591");
  snprintf(sysinfo.client_version, sizeof(sysinfo.client_version), "0.0.0");

  ret = librespotc_init(&sysinfo, &callbacks);
  if (ret < 0)
    {
      printf("Error initializing Spotify: %s\n", librespotc_last_errmsg());
      goto error;
    }

  f_stored_cred = fopen(argv[3], "rb");
  if (!f_stored_cred)
    {
      printf("Error opening file with stored credentials\n");
      goto error;
    }

  stored_cred_len = fread(stored_cred, 1, sizeof(stored_cred), f_stored_cred);
  if (stored_cred_len == 0)
    {
      printf("Stored credentials file is empty\n");
      goto error;
    }

  ret = librespot_http_test(argv[2], stored_cred, stored_cred_len);

  printf("%d\n", ret);

 error:
  fclose(f_stored_cred);
  librespotc_deinit();
  return ret;
}

#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <curl/curl.h>
#include <ctype.h> // for isprint()

/*
static void
hexdump_dummy(const char *msg, uint8_t *mem, size_t len)
{
  return;
}
*/

void
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

void
logmsg(const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  vprintf(fmt, ap);
  va_end(ap);
}

static size_t
https_write_cb(char *data, size_t size, size_t nmemb, void *userdata)
{
  char **body;
  size_t realsize;

  realsize = size * nmemb;
  body = (char **)userdata;

  *body = malloc(realsize + 1);
  memcpy(*body, data, realsize);
  (*body)[realsize] = 0;

  return realsize;
}

int
https_get(char **body, const char *url)
{
  CURL *curl;
  CURLcode res;
  long response_code;

  curl = curl_easy_init();
  if (!curl)
    {
      printf("Could not initialize CURL\n");
      goto error;
    }

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, https_write_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, body);

  res = curl_easy_perform(curl);
  if (res != CURLE_OK)
    {
      printf("CURL could not make request (%d)\n", (int)res);
      goto error;
    }

  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
  if (response_code != 200)
    {
      printf("HTTP response code %d\n", (int)response_code);
      goto error;
    }

  curl_easy_cleanup(curl);

  return 0;

 error:
  curl_easy_cleanup(curl);
  return -1;
}

int
tcp_connect(const char *address, unsigned short port)
{
  struct addrinfo hints = { 0 };
  struct addrinfo *servinfo;
  struct addrinfo *ptr;
  char strport[8];
  int fd;
  int ret;

  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;

  snprintf(strport, sizeof(strport), "%hu", port);
  ret = getaddrinfo(address, strport, &hints, &servinfo);
  if (ret < 0)
    {
      printf("Could not connect to %s (port %u): %s\n", address, port, gai_strerror(ret));
      return -1;
    }

  for (ptr = servinfo; ptr; ptr = ptr->ai_next)
    {
      fd = socket(ptr->ai_family, SOCK_STREAM, ptr->ai_protocol);
      if (fd < 0)
	{
	  continue;
	}

      ret = connect(fd, ptr->ai_addr, ptr->ai_addrlen);
      if (ret < 0)
	{
	  close(fd);
	  continue;
	}

      break;
    }

  freeaddrinfo(servinfo);

  if (!ptr)
    {
      printf("Could not connect to '%s' (port %u): %s\n", address, port, strerror(errno));
      return -1;
    }

  printf("Connected to %s (port %u)\n", address, port);

  return fd;
}

void
tcp_disconnect(int fd)
{
  if (fd < 0)
    return;

  close(fd);
}

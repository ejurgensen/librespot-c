#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// For file output
#include <sys/stat.h>
#include <fcntl.h>

#include <event2/event.h>
#include <event2/buffer.h>

#include "tests/utils.h"
#include "librespot-c.h"

static int audio_fd = -1;
static int test_file = -1;
static struct event_base *evbase;
static struct evbuffer *audio_buf;

static int total_bytes;

static void
progress_cb(int fd, void *arg, size_t received, size_t len)
{
  printf("Progress on fd %d is %zu/%zu\n", fd, received, len);
}

// This thread
static void
audio_read_cb(int fd, short what, void *arg)
{
  int got;

  got = evbuffer_read(audio_buf, fd, -1);
  if (got <= 0)
    {
      printf("Playback ended (%d)\n", got);
      event_base_loopbreak(evbase);
      return;
    }

  total_bytes += got;

  printf("Got %d bytes of audio, total received is %d bytes\n", got, total_bytes);

  evbuffer_write(audio_buf, test_file);
}

struct sp_callbacks callbacks =
{
  .https_get = https_get,
  .tcp_connect = tcp_connect,
  .tcp_disconnect = tcp_disconnect,

  .thread_name_set = NULL,

  .hexdump  = hexdump,
  .logmsg   = logmsg,
};

int
main(int argc, char * argv[])
{
  struct sp_session *session = NULL;
  struct sp_sysinfo sysinfo;
  struct sp_credentials credentials;
  struct sp_metadata metadata;
  struct event *read_ev;
//  struct event *stop_ev;
//  struct timeval tv = { 0 };
  int ret;

  if (argc != 4)
    {
      printf("%s spotify_path username password|token\n", argv[0]);
      goto error;
    }

  test_file = open("testfile.ogg", O_CREAT | O_RDWR, 0664);
  if (test_file < 0)
    {
      printf("Error opening file: %s\n", strerror(errno));
      goto error;
    }

  memset(&sysinfo, 0, sizeof(struct sp_sysinfo));
  snprintf(sysinfo.device_id, sizeof(sysinfo.device_id), "aabbccddeeff");

  ret = librespotc_init(&sysinfo, &callbacks);
  if (ret < 0)
    {
      printf("Error initializing Spotify: %s\n", librespotc_last_errmsg());
      goto error;
    }

  if (strlen(argv[3]) < 100)
    session = librespotc_login_password(argv[2], argv[3]);
  else
    session = librespotc_login_token(argv[2], argv[3]); // Length of token should be 194
  if (!session)
    {
      printf("Error logging in: %s\n", librespotc_last_errmsg());
      goto error;
    }

  printf("\n --- Login OK --- \n");

  ret = librespotc_credentials_get(&credentials, session);
  if (ret < 0)
    {
      printf("Error getting session credentials: %s\n", librespotc_last_errmsg());
      goto error;
    }

  printf("Username is %s\n", credentials.username);

  audio_fd = librespotc_open(argv[1], session);
  if (audio_fd < 0)
    {
      printf("Error opening file: %s\n", librespotc_last_errmsg());
      goto error;
    }

  ret = librespotc_metadata_get(&metadata, audio_fd);
  if (ret < 0)
    {
      printf("Error getting track metadata: %s\n", librespotc_last_errmsg());
      goto error;
    }

  printf("File is open, length is %zu\n", metadata.file_len);

  ret = librespotc_seek(audio_fd, 1000000);
  if (ret < 0)
    {
      printf("Error seeking: %s\n", librespotc_last_errmsg());
      goto error;
    }

  evbase = event_base_new();
  audio_buf = evbuffer_new();

  read_ev = event_new(evbase, audio_fd, EV_READ | EV_PERSIST, audio_read_cb, NULL);
  event_add(read_ev, NULL);

  librespotc_write(audio_fd, progress_cb, NULL);

//  stop_ev = evtimer_new(evbase, stop, &audio_fd);
//  tv.tv_sec = 2;
//  event_add(stop_ev, &tv);

  event_base_dispatch(evbase);

//  event_free(stop_ev);
  event_free(read_ev);

  evbuffer_free(audio_buf);

  event_base_free(evbase);

  librespotc_close(audio_fd);

  close(test_file);

  librespotc_logout(session);

  librespotc_deinit();

  return 0;

 error:
  if (audio_fd >= 0)
    librespotc_close(audio_fd);
  if (test_file >= 0)
    close(test_file);
  if (session)
    librespotc_logout(session);

  librespotc_deinit();

  return -1;
}

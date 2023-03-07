#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>

#include <event2/event.h>

#include <avahi-common/watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>
#include <avahi-client/publish.h>

// Hack for FreeBSD, don't want to bother with sysconf()
#ifndef HOST_NAME_MAX
# include <limits.h>
# define HOST_NAME_MAX _POSIX_HOST_NAME_MAX
#endif

#include "test2_mdns.h"

#define MDNSERR avahi_strerror(avahi_client_errno(mdns_client))


static struct event_base *mdns_evbase;

static AvahiClient *mdns_client = NULL;
static AvahiEntryGroup *mdns_group = NULL;
static AvahiIfIndex mdns_interface = AVAHI_IF_UNSPEC;


struct AvahiWatch
{
  struct event *ev;

  AvahiWatchCallback cb;
  void *userdata;

  AvahiWatch *next;
};

struct AvahiTimeout
{
  struct event *ev;

  AvahiTimeoutCallback cb;
  void *userdata;

  AvahiTimeout *next;
};

static AvahiWatch *all_w;
static AvahiTimeout *all_t;

/* libevent callbacks */

static void
evcb_watch(int fd, short ev_events, void *arg)
{
  AvahiWatch *w;
  AvahiWatchEvent a_events;

  w = (AvahiWatch *)arg;

  a_events = 0;
  if (ev_events & EV_READ)
    a_events |= AVAHI_WATCH_IN;
  if (ev_events & EV_WRITE)
    a_events |= AVAHI_WATCH_OUT;

  event_add(w->ev, NULL);

  w->cb(w, fd, a_events, w->userdata);
}

static void
evcb_timeout(int fd, short ev_events, void *arg)
{
  AvahiTimeout *t;

  t = (AvahiTimeout *)arg;

  t->cb(t, t->userdata);
}

/* AvahiPoll implementation for libevent */

static int
_ev_watch_add(AvahiWatch *w, int fd, AvahiWatchEvent a_events)
{
  short ev_events;

  ev_events = 0;
  if (a_events & AVAHI_WATCH_IN)
    ev_events |= EV_READ;
  if (a_events & AVAHI_WATCH_OUT)
    ev_events |= EV_WRITE;

  if (w->ev)
    event_free(w->ev);

  w->ev = event_new(mdns_evbase, fd, ev_events, evcb_watch, w);
  if (!w->ev)
    {
      printf("Could not make new event in _ev_watch_add\n");
      return -1;
    }

  return event_add(w->ev, NULL);
}

static AvahiWatch *
ev_watch_new(const AvahiPoll *api, int fd, AvahiWatchEvent a_events, AvahiWatchCallback cb, void *userdata)
{
  AvahiWatch *w;
  int ret;

  w = calloc(1, sizeof(AvahiWatch));
  if (!w)
    return NULL;

  w->cb = cb;
  w->userdata = userdata;

  ret = _ev_watch_add(w, fd, a_events);
  if (ret != 0)
    {
      free(w);
      return NULL;
    }

  w->next = all_w;
  all_w = w;

  return w;
}

static void
ev_watch_update(AvahiWatch *w, AvahiWatchEvent a_events)
{
  if (w->ev)
    event_del(w->ev);

  _ev_watch_add(w, (int)event_get_fd(w->ev), a_events);
}

static AvahiWatchEvent
ev_watch_get_events(AvahiWatch *w)
{
  AvahiWatchEvent a_events;

  a_events = 0;

  if (event_pending(w->ev, EV_READ, NULL))
    a_events |= AVAHI_WATCH_IN;
  if (event_pending(w->ev, EV_WRITE, NULL))
    a_events |= AVAHI_WATCH_OUT;

  return a_events;
}

static void
ev_watch_free(AvahiWatch *w)
{
  AvahiWatch *prev;
  AvahiWatch *cur;

  if (w->ev)
    {
      event_free(w->ev);
      w->ev = NULL;
    }

  prev = NULL;
  for (cur = all_w; cur; prev = cur, cur = cur->next)
    {
      if (cur != w)
	continue;

      if (prev == NULL)
	all_w = w->next;
      else
	prev->next = w->next;

      break;
    }

  free(w);
}

static int
_ev_timeout_add(AvahiTimeout *t, const struct timeval *tv)
{
  struct timeval e_tv;
  struct timeval now;
  int ret;

  if (t->ev)
    event_free(t->ev);

  t->ev = evtimer_new(mdns_evbase, evcb_timeout, t);
  if (!t->ev)
    {
      printf("Could not make event in _ev_timeout_add - out of memory?\n");
      return -1;
    }

  if ((tv->tv_sec == 0) && (tv->tv_usec == 0))
    {
      evutil_timerclear(&e_tv);
    }
  else
    {
      ret = gettimeofday(&now, NULL);
      if (ret != 0)
	return -1;

      evutil_timersub(tv, &now, &e_tv);
    }

  return evtimer_add(t->ev, &e_tv);
}

static AvahiTimeout *
ev_timeout_new(const AvahiPoll *api, const struct timeval *tv, AvahiTimeoutCallback cb, void *userdata)
{
  AvahiTimeout *t;
  int ret;

  t = calloc(1, sizeof(AvahiTimeout));
  if (!t)
    return NULL;

  t->cb = cb;
  t->userdata = userdata;

  if (tv != NULL)
    {
      ret = _ev_timeout_add(t, tv);
      if (ret != 0)
	{
	  free(t);

	  return NULL;
	}
    }

  t->next = all_t;
  all_t = t;

  return t;
}

static void
ev_timeout_update(AvahiTimeout *t, const struct timeval *tv)
{
  if (t->ev)
    event_del(t->ev);

  if (tv)
    _ev_timeout_add(t, tv);
}

static void
ev_timeout_free(AvahiTimeout *t)
{
  AvahiTimeout *prev;
  AvahiTimeout *cur;

  if (t->ev)
    {
      event_free(t->ev);
      t->ev = NULL;
    }

  prev = NULL;
  for (cur = all_t; cur; prev = cur, cur = cur->next)
    {
      if (cur != t)
	continue;

      if (prev == NULL)
	all_t = t->next;
      else
	prev->next = t->next;

      break;
    }

  free(t);
}

static struct AvahiPoll ev_poll_api =
  {
    .userdata = NULL,
    .watch_new = ev_watch_new,
    .watch_update = ev_watch_update,
    .watch_get_events = ev_watch_get_events,
    .watch_free = ev_watch_free,
    .timeout_new = ev_timeout_new,
    .timeout_update = ev_timeout_update,
    .timeout_free = ev_timeout_free
  };


/* Avahi client callbacks & helpers */

struct mdns_group_entry
{
  char *name;
  char *type;
  int port;
  AvahiStringList *txt;

  struct mdns_group_entry *next;
};

static struct mdns_group_entry *group_entries;

static void
group_entry_remove_all(struct mdns_group_entry **head)
{
  struct mdns_group_entry *ge;

  for (ge = *head; *head; ge = *head)
    {
      *head = ge->next;

      free(ge->name);
      free(ge->type);
      avahi_string_list_free(ge->txt);

      free(ge);
    }
}

static void
entry_group_callback(AvahiEntryGroup *g, AvahiEntryGroupState state, AVAHI_GCC_UNUSED void *userdata)
{
  if (!g || (g != mdns_group))
    return;

  switch (state)
    {
      case AVAHI_ENTRY_GROUP_ESTABLISHED:
        printf("Successfully added mDNS services\n");
        break;

      case AVAHI_ENTRY_GROUP_COLLISION:
        printf("Group collision\n");
        break;

      case AVAHI_ENTRY_GROUP_FAILURE:
        printf("Group failure\n");
        break;

      case AVAHI_ENTRY_GROUP_UNCOMMITED:
        printf("Group uncommitted\n");
	break;

      case AVAHI_ENTRY_GROUP_REGISTERING:
        printf("Group registering\n");
        break;
    }
}

static int
create_group_entry(struct mdns_group_entry *ge, int commit)
{
  int ret;

  if (!mdns_group)
    {
      mdns_group = avahi_entry_group_new(mdns_client, entry_group_callback, NULL);
      if (!mdns_group)
	{
	  printf("Could not create Avahi EntryGroup: %s\n", MDNSERR);
	  return -1;
	}
    }

  printf("Adding service %s/%s\n", ge->name, ge->type);

  ret = avahi_entry_group_add_service_strlst(mdns_group, mdns_interface, AVAHI_PROTO_UNSPEC, 0,
						 ge->name, ge->type,
						 NULL, NULL, ge->port, ge->txt);
  if (ret < 0)
    {
      printf("Could not add mDNS service %s/%s: %s\n", ge->name, ge->type, avahi_strerror(ret));
      return -1;
    }

  if (!commit)
    return 0;

  ret = avahi_entry_group_commit(mdns_group);
  if (ret < 0)
    {
      printf("Could not commit mDNS services: %s\n", MDNSERR);
      return -1;
    }

  return 0;
}

static void
create_all_group_entries(void)
{
  struct mdns_group_entry *ge;
  int ret;

  if (!group_entries)
    {
      printf("No entries yet... skipping service create\n");
      return;
    }

  if (mdns_group)
    avahi_entry_group_reset(mdns_group);

  printf("Re-registering mDNS groups (services and records)\n");

  for (ge = group_entries; ge; ge = ge->next)
    {
      create_group_entry(ge, 0);
      if (!mdns_group)
	return;
    }

  ret = avahi_entry_group_commit(mdns_group);
  if (ret < 0)
    printf("Could not commit mDNS services: %s\n", MDNSERR);
}

static void
client_callback(AvahiClient *c, AvahiClientState state, AVAHI_GCC_UNUSED void * userdata)
{
  int error;

  switch (state)
    {
      case AVAHI_CLIENT_S_RUNNING:
        printf("Avahi state change: Client running\n");
        if (!mdns_group)
	  create_all_group_entries();

        break;

      case AVAHI_CLIENT_S_COLLISION:
        printf("Avahi state change: Client collision\n");
        if(mdns_group)
	  avahi_entry_group_reset(mdns_group);
        break;

      case AVAHI_CLIENT_FAILURE:
        printf("Avahi state change: Client failure\n");

	error = avahi_client_errno(c);
	if (error == AVAHI_ERR_DISCONNECTED)
	  {
	    printf("Avahi Server disconnected, reconnecting\n");

	    avahi_client_free(mdns_client);
	    mdns_group = NULL;

	    mdns_client = avahi_client_new(&ev_poll_api, AVAHI_CLIENT_NO_FAIL, client_callback, NULL, &error);
	    if (!mdns_client)
	      printf("Failed to create new Avahi client: %s\n", avahi_strerror(error));
	  }
	else
	  {
	    printf("Avahi client failure: %s\n", avahi_strerror(error));
	  }
        break;

      case AVAHI_CLIENT_S_REGISTERING:
        printf("Avahi state change: Client registering\n");
        if (mdns_group)
	  avahi_entry_group_reset(mdns_group);
        break;

      case AVAHI_CLIENT_CONNECTING:
        printf("Avahi state change: Client connecting\n");
        break;
    }
}


int
mdns_init(struct event_base *evbase)
{
  int error;

  mdns_evbase = evbase;

  mdns_client = avahi_client_new(&ev_poll_api, AVAHI_CLIENT_NO_FAIL, client_callback, NULL, &error);
  if (!mdns_client)
    {
      printf("mdns_init: Could not create Avahi client: %s\n", avahi_strerror(error));
      return -1;
    }

  return 0;
}

void
mdns_deinit(void)
{
  group_entry_remove_all(&group_entries);

  if (mdns_client)
    avahi_client_free(mdns_client); // Also frees all_w and all_t
}

int
mdns_register(char *name, char *type, int port, char **txt)
{
  struct mdns_group_entry *ge;
  AvahiStringList *txt_sl;
  int i;

  ge = calloc(1, sizeof(struct mdns_group_entry));
  if (!ge)
    {
      printf("Out of memory for mdns register\n");
      return -1;
    }

  ge->name = strdup(name);
  ge->type = strdup(type);
  ge->port = port;

  txt_sl = NULL;
  if (txt)
    {
      for (i = 0; txt[i]; i++)
	{
	  txt_sl = avahi_string_list_add(txt_sl, txt[i]);

	  printf("Added key %s\n", txt[i]);
	}
    }

  ge->txt = txt_sl;

  ge->next = group_entries;
  group_entries = ge;

  create_all_group_entries();

  return 0;
}

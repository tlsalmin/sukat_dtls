#include <errno.h>
#include <string.h>

#define LOG_DESCRIPTION "sukat_epoll"

#include "sukat_epoll.h"
#include "sukat_log_internal.h"

bool sukat_epoll_reg(int efd, int fd, union epoll_data *data, uint32_t events)
{
  int ret;
  struct epoll_event ev =
    {
      .events = events,
      .data = *data
    };

  ret = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev);
  if (ret == -1 && errno == EEXIST)
    {
      ret = epoll_ctl(efd, EPOLL_CTL_MOD, fd, &ev);
    }
  if (ret)
    {
      ERR("Failed to add fd %d events %u to efd %d: %s", fd, events, efd,
          strerror(errno));
    }
  return !ret;
}

bool sukat_epoll_remove(int efd, int fd)
{
  struct epoll_event ev = {};

  if (epoll_ctl(efd, EPOLL_CTL_DEL, fd, &ev))
    {
      ERR("Failed to remove %d from efd %d: %s", fd, efd, strerror(errno));
      return false;
    }
  return true;
}

int sukat_epoll_wait(int efd, sukat_epoll_cb cb, void *context, int timeout)
{
  const unsigned int max_events = 128;
  struct epoll_event ev[max_events];
  int ret;

  ret = epoll_wait(efd, ev, max_events, timeout);
  if (ret >= 0)
    {
      unsigned int n_events = (unsigned int)ret, i;

      for (i = 0; i < n_events; i++)
        {
          ret = cb(context, ev[i].events, &ev[i].data);
          if (ret)
            {
              break;
            }
        }
    }
  else
    {
      ERR("Failed to wait for events on fd %d: %s", efd, strerror(errno));
    }
  return ret;
}

#include <sys/types.h>
#include <netdb.h>
#include <stdio.h>
#include <assert.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

#define LOG_DESCRIPTION "sukat_util"

#include "sukat_util.h"
#include "sukat_log_internal.h"

char *sukat_util_storage_print(struct sockaddr *saddr,
                               char *buf, size_t buf_len)
{
  char *ret = NULL;

  if (saddr->sa_family == AF_INET || saddr->sa_family == AF_INET6)
    {
      bool ipv6 = (saddr->sa_family == AF_INET6);
      char ipstr[INET6_ADDRSTRLEN];
      void *src;
      in_port_t port;

      if (ipv6)
        {
          struct sockaddr_in6 *sin = (struct sockaddr_in6 *)saddr;

          src = &sin->sin6_addr;
          port = ntohs(sin->sin6_port);
        }
      else
        {
          struct sockaddr_in *sin = (struct sockaddr_in *)saddr;

          src = &sin->sin_addr;
          port = ntohs(sin->sin_port);
        }

      if (inet_ntop(saddr->sa_family, src, ipstr, sizeof(ipstr)))
        {
          snprintf(buf, buf_len, "%s:%hu", ipstr, port);
          ret = buf;
        }
      else
        {
          ERR("Failed to convert saddr to string");
        }
    }
  else
    {
      ERR("Unknown family %d for printing", saddr->sa_family);
    }
  return ret;
}

bool sukat_util_solve(const char *addr, const char *port,
                              int type, struct sockaddr_storage *saddr,
                              socklen_t *slen, sukat_util_fd_opts_t opts)
{
  struct addrinfo hints = {}, *res = NULL;
  int ret;
  bool status = false;

  if (!saddr || !slen)
    {
      ERR("Faulty param saddr %p, slen %p to solve", saddr, slen);
      return false;
    }

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = type;
  if (opts & sukat_sockopt_numeric)
    {
      hints.ai_flags = AI_NUMERICHOST;
    }
  if (!addr)
    {
      hints.ai_flags |= AI_PASSIVE;
    }
  else if (opts & sukat_sockopt_bind)
    {
      hints.ai_flags |= AI_ADDRCONFIG;
    }
  ret = getaddrinfo(addr, port, &hints, &res);

  if (!ret)
    {
      if (res)
        {
          char ipstr[IPSTRLEN];

          assert(res->ai_addrlen <= sizeof(*saddr));
          *slen = res->ai_addrlen;
          memcpy(saddr, res->ai_addr, res->ai_addrlen);

          DBG("Solved %s:%s to %s", addr, port,
              sukat_util_storage_print((struct sockaddr *)saddr, ipstr,
                                       sizeof(ipstr)));

          status = true;
        }
      else
        {
          ERR("Address solved, but no resolutions");
        }
      freeaddrinfo(res);
    }
  else
    {
      ERR("Failed to solve addr: %s, port: %s, type: %d : %s", addr, port,
          type, gai_strerror(ret));
    }
  return status;
}


void sukat_util_fd_safe_close(int *fd)
{
  if (fd && *fd != -1)
    {
      int ret = close(*fd);

      if (ret == -1)
        {
          int stored_errno = errno;

          ERR("Failed to close fd %d: %s", *fd, strerror(stored_errno));
          assert(stored_errno != EBADF);
          if (stored_errno == EINTR)
            {
              // Some recursion, what's the worst that can happen?
              sukat_util_fd_safe_close(fd);
            }
        }
      else
        {
          *fd = -1;
        }
    }
}

bool sukat_util_sockopts(int fd, sukat_util_fd_opts_t opts)
{
  int yes = 1, no = 0;

  if ((!(opts & sukat_sockopt_reuseaddr) ||
       !(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)))) &&
      (!(opts & sukat_sockopt_reuseport) ||
       !(setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes)))) &&
      (!(opts & sukat_sockopt_v6andv4) ||
       !(setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no)))))
    {
      return true;
    }
  else
    {
      ERR("Failed to do opts %d on fd %d: %s", opts, fd, strerror(errno));
    }
  return false;
}

int sukat_util_fd_create(const char *addr, const char *port, int type,
                         sukat_util_fd_opts_t opts, struct sockaddr *saddr,
                         socklen_t *saddr_len)
{
  int fd = -1;
  struct sockaddr_storage bind_to = {};
  struct sockaddr_in *bind_to_4 = (struct sockaddr_in *)&bind_to;
  struct sockaddr_in6 *bind_to_6 = (struct sockaddr_in6 *)&bind_to;
  socklen_t slen = sizeof(bind_to);

  if (!addr && !port)
    {
      // Default for combined.
      bind_to.ss_family = AF_INET6;
    }
  else if (!addr && port)
    {
      uint16_t port_int = atoi(port);

      if (bind_to.ss_family == AF_INET6)
        {
          bind_to_6->sin6_port = htons(port_int);
        }
      else
        {
          bind_to_4->sin_port = htons(port_int);
        }
    }
  else if (!sukat_util_solve(addr, port, type, &bind_to, &slen, opts))
    {
      ERR("Failed to solve ip %s port %s", addr, port);
    }
  if (opts & sukat_sockopt_nonblock)
    {
      type |= SOCK_NONBLOCK;
    }
  if (opts & sukat_sockopt_cloexec)
    {
      type |= SOCK_CLOEXEC;
    }

  fd = socket(bind_to.ss_family, type, 0);
  if (fd != -1)
    {
      if (sukat_util_sockopts(fd, opts))
        {
          if (!(opts & sukat_sockopt_bind) ||
              !bind(fd, (struct sockaddr *)&bind_to, slen))
            {
              /* Word of warning. This connect will return -1 && errno ==
               * EINPROGRESS for TCP-connections */
              if (!(opts & sukat_sockopt_connect) ||
                  !connect(fd, (struct sockaddr *)&bind_to, slen))
                {
                  if (saddr && saddr_len)
                    {
                      memcpy(saddr, &bind_to,
                             (slen > *saddr_len) ? slen : *saddr_len);
                      *saddr_len = slen;
                    }
                  return fd;
                }
            }
          else
            {
              char ipstr[IPSTRLEN];

              ERR("Failed to bind fd %d to %s: %s", fd,
                  sukat_util_storage_print((struct sockaddr *)&bind_to, ipstr,
                                           sizeof(ipstr)),
                  strerror(errno));
            }
        }
      else
        {
          ERR("Failed to sockopt or bind fd %d: %s", fd, strerror(errno));
        }
      sukat_util_fd_safe_close(&fd);
    }
  else
    {
      ERR("Failed to created socket: %s", strerror(errno));
    }
  return fd;
}

int sukat_util_peek_peer(int fd, struct sockaddr *saddr, socklen_t slen)
{
  char buf[BUFSIZ];
  ssize_t ret;
  struct iovec iov =
    {
      .iov_base = buf,
      .iov_len = sizeof(buf)
    };
  struct msghdr hdr =
    {
      .msg_name = saddr,
      .msg_namelen = slen,
      .msg_iov = &iov
    };

  ret = recvmsg(fd, &hdr, MSG_PEEK);
  if (ret >= 0)
    {
      char ipstr[IPSTRLEN];

      DBG("Peaked peer behind fd %d to %s", fd,
          sukat_util_storage_print(saddr, ipstr, sizeof(ipstr)));
      return hdr.msg_namelen;
    }
  else
    {
      ERR("Failed to peek from fd %d: %s", fd,
          (!ret) ? "closed" : strerror(errno));
    }
  return -1;
}

int sukat_util_fd_duplicate(int bound_fd, int type,
                            struct sockaddr_storage *peer,
                            socklen_t slen, sukat_util_fd_opts_t opts)
{
  struct sockaddr_storage bound_to = {};
  socklen_t bound_to_slen = sizeof(bound_to);

  if (!getsockname(bound_fd, (struct sockaddr *)&bound_to, &bound_to_slen))
    {
      int fd = socket(bound_to.ss_family, type | SOCK_NONBLOCK | SOCK_CLOEXEC,
                      0);

      if (fd != -1)
        {
          if (sukat_util_sockopts(fd, opts))
            {
              char ipstr[IPSTRLEN];

              if (!(opts & sukat_sockopt_bind) ||
                  !bind(fd, (struct sockaddr *)&bound_to, bound_to_slen))
                {
                  if (!connect(fd, (struct sockaddr *)peer, slen))
                    {
                      return fd;
                    }
                  else
                    {
                      ERR("Failed to connect bound fd %d to %s: %s", fd,
                          sukat_util_storage_print((struct sockaddr *)peer,
                                                   ipstr, sizeof(ipstr)),
                          strerror(errno));
                    }
                }
              else
                {

                  ERR("Failed to bind %d to %s: %s", fd,
                      sukat_util_storage_print((struct sockaddr *)&bound_to,
                                               ipstr, sizeof(ipstr)),
                      strerror(errno));
                }
            }
          sukat_util_fd_safe_close(&fd);
        }
      else
        {
          ERR("Failed to create socket type %d: %s", type, strerror(errno));
        }
    }
  else
    {
      ERR("Couldn't solve where fd %d was bound to: %s", bound_fd,
          strerror(errno));
    }
  return -1;
}


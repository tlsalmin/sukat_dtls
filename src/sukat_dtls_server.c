#include <sys/epoll.h>
#include <assert.h>
#include <netdb.h>
#include <sys/types.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "sukat_dtls.h"
#include "sukat_log_internal.h"
#include "sukat_util.h"
#include "sukat_epoll.h"

#define LOG_DESCRIPTION "sukat_dtls"

/** @brief Main DTLS server context internally */
struct sukat_dtls_server_context
{
  SSL_CTX *ssl_ctx; //!< SSL_CTX for new connections.
  void *context;    //!< User given context.
  int udp_fd;       //!< UDP listening socket.
  int efd;          //!< Event fd for clients.
  struct sukat_dtls_server_cbs cbs; //!< Callback registered.
  sukat_dtls_client_event_t subscribed; //!< Events caller has subscribed to.
};

/** @brief Context per client */
struct sukat_dtls_client_context
{
  SSL *ssl;                     //!< SSL context.
  struct sockaddr_storage peer; //!< Peer IP address.
  socklen_t slen;               //!< Length of Peer IP data.
  bool handshake_finished;      //!< SSL_accept finished.
  bool dtls_finished;           //!< DTLSv1_listen finished.
};

sukat_dtls_server_t *sukat_dtls_server_init(
  struct sukat_dtls_server_options *opts)
{
  sukat_dtls_server_t *ctx;

  if (!opts || !opts->ssl_ctx)
    {
      ERR("No %s for dtls server", (opts) ? "Options" : "SSL context");
      return NULL;
    }
  ctx = calloc(1, sizeof(*ctx));

  if (ctx)
    {
      ctx->udp_fd = ctx->efd = -1;
      ctx->ssl_ctx = opts->ssl_ctx;
      ctx->cbs = opts->cbs;
      ctx->subscribed = opts->subscribed_events;
      ctx->context = opts->context;

      INF("Created context %p for DTLS server on %s:%s", ctx,
          (opts->host) ? opts->host : "INADDR_ANY",
          (opts->port) ? opts->port : "0");
      ctx->efd = epoll_create1(EPOLL_CLOEXEC);
      if (ctx->efd != -1)
        {
          sukat_util_fd_opts_t sock_opts = sukat_sockopt_reuseaddr |
                                           sukat_sockopt_reuseport |
                                           sukat_sockopt_bind |
                                           sukat_sockopt_numeric |
                                           sukat_sockopt_nonblock |
                                           sukat_sockopt_cloexec;

          if (!opts->host)
            {
              sock_opts |= sukat_sockopt_v6andv4;
            }
          ctx->udp_fd =
            sukat_util_fd_create(opts->host, opts->port, SOCK_DGRAM, sock_opts,
                                 NULL, NULL);

          if (ctx->udp_fd != -1)
            {
              union epoll_data e_data =
                {
                  e_data.ptr = ctx
                };

              if (sukat_epoll_reg(ctx->efd, ctx->udp_fd, &e_data, EPOLLIN))
                {
                  return ctx;
                }
              sukat_util_fd_safe_close(&ctx->udp_fd);
            }
          else
            {
              ERR("Failed to create socket for dtls");
            }
          sukat_util_fd_safe_close(&ctx->efd);
        }
      else
        {
          ERR("Failed to create epoll fd: %s", strerror(errno));
        }
      free(ctx);
    }
  else
    {
      ERR("Failed to allocate context for DTLS server: %s", strerror(errno));
    }

  return NULL;
}

int sukat_dtls_server_efd(sukat_dtls_server_t *ctx)
{
  return ctx->efd;
}

/** @brief Handles the DTLS listen step for connections */
int sukat_dtls_listen_step(sukat_dtls_client_t *client,
                           uint32_t *events)
{
  char errbuf[BUFSIZ];
  int sslerr = 0;
  /* Dummy, since sockaddr from peek is always set, unlike
   * with a call to DTLSV1_listen */
  struct sockaddr_storage dtls_peer = {};
  int ret = DTLSv1_listen(client->ssl, &dtls_peer);

  if (ret <= 0)
    {
      sslerr = SSL_get_error(client->ssl, ret);
      ERR_clear_error();
    }
  if (ret == 1 ||
      (sslerr = SSL_ERROR_WANT_READ || sslerr == SSL_ERROR_WANT_WRITE))
    {
      client->dtls_finished = (ret == 1);
      *events = EPOLLIN;

      if (ret == 1)
        {
          INF("Client %p from %s DTLS handshake finished", client,
              sukat_util_storage_print((struct sockaddr *)&dtls_peer, errbuf,
                                       sizeof(errbuf)));
        }
      else
        {
          ret = 0;
        }
      if (sslerr == SSL_ERROR_WANT_WRITE)
        {
          *events |= EPOLLOUT;
        }

      return ret;
    }
  ERR("Failed to DTLS accept a new client: %s",
      ERR_error_string(sslerr, errbuf));
  return -1;
}

void sukat_dtls_client_destroy(sukat_dtls_server_t *ctx,
                               sukat_dtls_client_t *client)
{
  if (client)
    {
      if (client->ssl)
        {
          if (ctx)
            {
              int fd = BIO_get_fd(SSL_get_rbio(client->ssl), NULL);

              if (fd >= 0)
                {
                  // Fd might already be removed.
                  sukat_epoll_remove(ctx->efd, fd);
                }
            }
          // TODO: Check safety.
          SSL_shutdown(client->ssl);
          SSL_free(client->ssl);
        }
      free(client);
    }
}

static void sukat_dtls_new_client_register(sukat_dtls_server_t *ctx,
                                           sukat_dtls_client_t *client)
{
  char ipstr[IPSTRLEN];

  INF("Accepted new client from %s",
      sukat_util_storage_print((struct sockaddr *)&client->peer, ipstr,
                               sizeof(ipstr)));

  if (ctx->cbs.event_cb &&
      (ctx->subscribed & sukat_dtls_client_event_connected))
    {
      ctx->cbs.event_cb(ctx->context, client,
                        sukat_dtls_client_event_connected);
    }
}

/** @brief Accepts a new UDP connection.
 *
 * Yes UDP connections aren't really accepted, but by creating a new socket,
 * which is connected to the new peer, we can separate the UDP clients into
 * "accepted" fds */
static int sukat_dtls_new_client(sukat_dtls_server_t *ctx)
{
  struct sockaddr_storage peer;
  int peek_ret;
  struct sockaddr_storage bound_store = { };
  socklen_t bound_store_len = sizeof(bound_store);

  if (getsockname(ctx->udp_fd, (struct sockaddr *)&bound_store,
                  &bound_store_len))
    {
      ERR("Failed to get sockname from %d: %s", ctx->udp_fd, strerror(errno));
      return -1;
    }
  // Accept new clients in a loop, since that's how we roll.
  while ((peek_ret = sukat_util_peek_peer(ctx->udp_fd, (struct sockaddr *)&peer,
                                          sizeof(peer))) > 0)
    {
      /* The trick with UDP servers is to have the main fd be SO_REUSEADDR |
       * SO_REUSEPORT and any client-connected fds to be only SO_REUSEADDR */
      sukat_util_fd_opts_t opts =
        (sukat_sockopt_reuseaddr | sukat_sockopt_bind);
      int new_fd;

      new_fd =
        sukat_util_fd_duplicate(ctx->udp_fd, SOCK_DGRAM, &peer, peek_ret, opts);
      if (new_fd != -1)
        {
          sukat_dtls_client_t *client = calloc(1, sizeof(*client));

          // This could be broken down to smaller funcs, but later.
          if (client)
            {
              char errbuf[512];

              client->ssl = SSL_new(ctx->ssl_ctx);
              memcpy(&client->peer, &peer, peek_ret);
              client->slen = peek_ret;

              if (client->ssl)
                {
                  BIO *bio;
                  SSL_set_options(client->ssl, SSL_OP_COOKIE_EXCHANGE);

                  bio = BIO_new_dgram(ctx->udp_fd, BIO_NOCLOSE);
                  if (bio)
                    {
                      uint32_t events = EPOLLIN;
                      int ret;

                      SSL_set_bio(client->ssl, bio, bio);

                      ret = sukat_dtls_listen_step(client, &events);
                      BIO_set_fd(bio, new_fd, BIO_CLOSE);
                      BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0,
                               &client->peer);
                      if (ret >= 0)
                        {
                          union epoll_data edata = {.ptr = client};

                          client->dtls_finished = (ret == 1);
                          if (sukat_epoll_reg(ctx->efd, new_fd, &edata, events))
                            {
                              sukat_dtls_new_client_register(ctx, client);
                              // Try to get another one.
                              continue;
                            }
                          else
                            {
                              ERR("Failed to register fd %ld to efd %d: %s",
                                  BIO_get_fd(SSL_get_rbio(client->ssl), NULL),
                                  ctx->efd, strerror(errno));
                            }
                        }
                      // fd gets closed with SSL.
                      new_fd = -1;
                      // Bio gets destroyed with SSL.
                    }
                  else
                    {
                      ERR("Failed to create new bio: %s",
                          ERR_error_string(ERR_get_error(), errbuf));
                    }
                  SSL_free(client->ssl);
                }
              else
                {
                  ERR("Failed to create new SSL from %p: %s", ctx->ssl_ctx,
                      ERR_error_string(ERR_get_error(), errbuf));
                }
              free(client);
            }
          else
            {
              ERR("Failed to allocate new client: %s", strerror(errno));
            }
          sukat_util_fd_safe_close(&new_fd);
        }
      else
        {
          ERR("Failed to duplicate fd %d: %s", ctx->udp_fd, strerror(errno));
        }
    }

  return 0;
}

static int sukat_dtls_client_accept(sukat_dtls_server_t *ctx,
                                    sukat_dtls_client_t *client)
{
  int ret = -1;
  int fd = BIO_get_fd(SSL_get_rbio(client->ssl), NULL);
  uint32_t events = EPOLLIN;

  // First remove from epoll, only to add later with refreshed events.
  if (!sukat_epoll_remove(ctx->efd, fd))
    {
      ERR("Failed to remove fd %d from efd %d: %s", fd, ctx->efd,
          strerror(errno));
    }
  if (!client->dtls_finished)
    {
      ret = sukat_dtls_listen_step(client, &events);

      if (ret >= 0)
        {
          if (ret == 1)
            {
              char ipstr[IPSTRLEN];

              DBG("Client %p from %s dtls handshake_finished", client,
                  sukat_util_storage_print((struct sockaddr *)&client->peer, ipstr,
                                           sizeof(ipstr)));
              client->dtls_finished = true;
            }
          else
            {
              DBG("Client %p still needs more %s", client,
                  (events & EPOLLOUT) ? "write" : "read");
            }
          ret = 0;
        }
    }
  if (client->dtls_finished && !client->handshake_finished)
    {
      ret = SSL_accept(client->ssl);
      int sslerr = 0;

      if (ret <= 0)
        {
          sslerr = SSL_get_error(client->ssl, ret);
          ERR_clear_error();
        }
      DBG("SSl accept for client %p returned %d, sslerr %d", client, ret,
          sslerr);
      if (ret == 1 ||
          (sslerr == SSL_ERROR_WANT_READ || sslerr == SSL_ERROR_WANT_WRITE))
        {
          events = EPOLLIN;
          if (ret == 1)
            {
              INF("Client %p handshake finished", client);
              client->handshake_finished = true;

              if (ctx->cbs.event_cb &&
                  (ctx->subscribed & sukat_dtls_client_event_established))
                {
                  // TODO: If client disconnected here, we're in big trouble.
                  ctx->cbs.event_cb(ctx->context, client,
                                    sukat_dtls_client_event_established);
                }
            }
          else
            {
              DBG("Client %p needs more %s", client,
                  (sslerr == SSL_ERROR_WANT_WRITE) ? "write" : "read");
              if (sslerr == SSL_ERROR_WANT_WRITE)
                {
                  events |= EPOLLOUT;
                }
            }
          ret = 0;
        }
      else
        {
          char ipstr[IPSTRLEN], errbuf[BUFSIZ];

          ERR("Failed to accept client %p from %s handshake: %s",
              client, sukat_util_storage_print((struct sockaddr *)&client->peer,
                                               ipstr, sizeof(ipstr)),
              ERR_error_string(sslerr, errbuf));

        }
    }
  // Re-add client back to efd with refreshed events.
  if (!ret)
    {
      union epoll_data ev_data =
        {
          .ptr = client
        };

      if (!sukat_epoll_reg(ctx->efd, fd, &ev_data, events))
        {
          ERR("Failed to return client %p fd %d to efd %d: %s",
              client, fd, ctx->efd, strerror(errno));
          ret = -1;
        }
    }
  return ret;
}

static int sukat_dtls_client_readable(sukat_dtls_server_t *ctx,
                                  sukat_dtls_client_t *client)
{
  int ret = 0;

  if (!client->dtls_finished || !client->handshake_finished)
    {
      DBG("Continuing %s handshake of client %p",
          (client->dtls_finished) ? "ssl" : "dtls", client);
      ret = sukat_dtls_client_accept(ctx, client);
    }
  else
    {
      DBG_SPAM("Func to invoke: %p", ctx->cbs.event_cb);
      if (ctx->cbs.event_cb &&
          (ctx->subscribed & sukat_dtls_client_event_data_readable))
        {
          ctx->cbs.event_cb(ctx->context, client,
                            sukat_dtls_client_event_data_readable);
        }
      else
        {
          DBG("Client %p not subscribed to read events", client);
        }
    }
  return ret;
}

static int sukat_dtls_epoll_cb(void *context, uint32_t events,
                               union epoll_data *data)
{
  sukat_dtls_server_t *ctx = context;

  DBG("Events %u on data %p, main_ctx %p", events, data->ptr, ctx);

  // Data in main fd.
  if (data->ptr == ctx)
    {
      // Client accepting is non-fatal if failed.
      sukat_dtls_new_client(ctx);
    }
  // Data in client fd.
  else
    {
      sukat_dtls_client_t *client = data->ptr;

      DBG("Data from client %p", client);
      assert(client);
      if (sukat_dtls_client_readable(ctx, client))
        {
          DBG("Client %p ordered removal", client);
          sukat_dtls_client_destroy(ctx, client);
        }
    }
  return 0;
}

// This might be a bit silly, but lets try it.
union buf_rw
{
  uint8_t *read_buf;
  const uint8_t *write_buf;
};

static int sukat_dtls_client_rw(sukat_dtls_client_t *client, union buf_rw *buf,
                                size_t buf_size, bool write)
{
  int ret = -1;
  const char *op = (write) ? "write" : "read";

  if (client && buf && buf_size)
    {
      if (client->dtls_finished && client->handshake_finished)
        {
          int sslerr;

          ret = (write) ? SSL_write(client->ssl, buf->write_buf, buf_size)
                        : SSL_read(client->ssl, buf->read_buf, buf_size);

          if (ret > 0)
            {
              DBG_SPAM("%s %d bytes from client %p", (write) ? "wrote" : "read",
                       ret, client);
              return ret;
            }
          sslerr = SSL_get_error(client->ssl, ret);
          ERR_clear_error();

          if (sslerr == SSL_ERROR_WANT_READ ||
              sslerr == SSL_ERROR_WANT_WRITE)
            {
              ret = -1;
              errno = EAGAIN;
            }
          else
            {
              char errbuf[BUFSIZ];

              ERR("Failed to %s %zu bytes from client %p: %s", op,
                  buf_size, client, ERR_error_string(sslerr, errbuf));
            }
        }
      else
        {
          ERR("Client %p handshake not yet finished", client);
          errno = EINVAL;
        }
    }
  else
    {
      ERR("Invalid argument client: %p, buf: %p, buf_len: %zu to %s",
          client, buf, buf_size, op);
      errno = EINVAL;
    }
  return ret;
}

int sukat_dtls_client_read(sukat_dtls_client_t *client, uint8_t *buf,
                           size_t buf_size)
{
  union buf_rw rwbuf =
    {
      .read_buf = buf
    };

  return sukat_dtls_client_rw(client, &rwbuf, buf_size, false);
}

int sukat_dtls_client_write(sukat_dtls_client_t *client, const uint8_t *buf,
                            size_t buf_len)
{
  union buf_rw rwbuf =
    {
      .write_buf = buf
    };

  return sukat_dtls_client_rw(client, &rwbuf, buf_len, true);
}

int sukat_dtls_server_process(sukat_dtls_server_t *ctx, int timeout)
{
  return sukat_epoll_wait(ctx->efd, sukat_dtls_epoll_cb, ctx, timeout);
}


struct sockaddr *sukat_dtls_client_get_peer(sukat_dtls_client_t *client,
                                            socklen_t *slen)
{
  if (client)
    {
      if (slen)
        {
          *slen = client->slen;
        }
      return (struct sockaddr *)&client->peer;
    }
  return NULL;
}

char *sukat_dtls_client_to_string(sukat_dtls_client_t *client,
                                  char *buf, size_t buf_size)
{
  return sukat_util_storage_print(sukat_dtls_client_get_peer(client, NULL),
                                  buf, buf_size);
}

SSL *sukat_dtls_client_get_ssl(sukat_dtls_client_t *client)
{
  if (client)
    {
      return client->ssl;
    }
  return NULL;
}

int sukat_dtls_client_continue(sukat_dtls_client_t *client, uint32_t *events)
{
  int ret =-1;
  *events = EPOLLIN;

  if (!client->handshake_finished)
    {
      ret = SSL_connect(client->ssl);
      int sslerr;

      if (ret != 1)
        {
          sslerr = SSL_get_error(client->ssl, ret);
          ERR_clear_error();
        }
      if (ret == 1 ||
          (sslerr == SSL_ERROR_WANT_READ || sslerr == SSL_ERROR_WANT_WRITE))
        {
          if (ret == 1)
            {
              INF("Client %p handshake finished", client);
              client->handshake_finished = client->dtls_finished = true;
            }
          else
            {
              DBG("Client %p connect still needs more %s", client,
                  (sslerr == SSL_ERROR_WANT_WRITE) ? "write" : "read");
              ret = 0;
              if (sslerr == SSL_ERROR_WANT_WRITE)
                {
                  *events |= EPOLLOUT;
                }
            }
        }
      else
        {
          char errbuf[BUFSIZ];

          ERR("Failed to SSL_connect client %p: %s", client,
              ERR_error_string(sslerr, errbuf));
          ret = -1;
        }
    }

  return ret;
}

int sukat_dtls_client_connect(SSL_CTX *ssl_ctx, const char *dst,
                              const char *port, sukat_dtls_client_t **client,
                              uint32_t *events)
{
  if (*client)
    {
      DBG("Continuing client %p connection", *client);
      return sukat_dtls_client_continue(*client, events);
    }
  else
    {
      sukat_dtls_client_t *new_client = calloc(1, sizeof(*new_client));

      if (new_client)
        {
          int fd;
          sukat_util_fd_opts_t opts = sukat_sockopt_connect |
                                      sukat_sockopt_nonblock |
                                      sukat_sockopt_cloexec;
          new_client->slen = sizeof(new_client->peer);

          fd = sukat_util_fd_create(dst, port, SOCK_DGRAM, opts,
                                    (struct sockaddr *)&new_client->peer,
                                    &new_client->slen);
          if (fd != -1)
            {
              char errbuf[BUFSIZ];
              BIO *bio = BIO_new_dgram(fd, BIO_CLOSE);

              if (bio)
                {
                  new_client->ssl = SSL_new(ssl_ctx);
                  BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0,
                           &new_client->peer);

                  if (new_client->ssl)
                    {
                      SSL_set_bio(new_client->ssl, bio, bio);

                      if (!sukat_dtls_client_continue(new_client, events))
                        {
                          *client = new_client;
                          return 0;
                        }
                      SSL_free(new_client->ssl);
                    }
                  else
                    {
                      ERR("Failed to create new SSL from %p: %s", ssl_ctx,
                          ERR_error_string(ERR_get_error(), errbuf));
                      BIO_free(bio);
                    }
                }
              else
                {
                  ERR("Failed to create new dgram bio from %d: %s", fd,
                      ERR_error_string(ERR_get_error(), errbuf));
                  sukat_util_fd_safe_close(&fd);
                }
            }
          else
            {
              ERR("Failed to create socket: %s", strerror(errno));
            }
          free(new_client);
        }
      else
        {
          ERR("Failed to allocate client context: %s", strerror(errno));
        }
    }
  return -1;
}

void sukat_dtls_server_destroy(sukat_dtls_server_t *ctx)
{
  if (ctx)
    {
      sukat_util_fd_safe_close(&ctx->udp_fd);
      sukat_util_fd_safe_close(&ctx->efd);
      free(ctx);
    }
}

uint16_t sukat_dtls_server_port(sukat_dtls_server_t *ctx)
{
  uint16_t port = 0;

  if (ctx)
    {
      struct sockaddr_storage saddr = {};
      socklen_t slen = sizeof(saddr);

      if (!getsockname(ctx->udp_fd, (struct sockaddr *)&saddr, &slen))
        {
          port = (saddr.ss_family == AF_INET6)
                   ? ntohs(((struct sockaddr_in6 *)&saddr)->sin6_port)
                   : ((saddr.ss_family == AF_INET)
                        ? ntohs(((struct sockaddr_in *)&saddr)->sin_port)
                        : 0);

          if (!port)
            {
              // Aliens!
              ERR("Unknown family %hu", saddr.ss_family);
            }
          else
            {
              DBG("Server %p hosted on port %hu", ctx, port);
            }
        }
      else
        {
          ERR("Failed to getsockname for fd %d: %s", ctx->udp_fd,
              strerror(errno));
        }
    }
  return port;
}

bool sukat_dtls_getsockname(sukat_dtls_server_t *ctx,
                            struct sockaddr_storage *saddr,
                            socklen_t *slen)
{
  if (ctx && saddr && slen)
    {
      if (!getsockname(ctx->udp_fd, (struct sockaddr *)saddr, slen))
        {
          return true;
        }
      else
        {
          ERR("Failed to query fd %d getsockname: %s", ctx->udp_fd,
              strerror(errno));
        }
    }
  return false;
}

char *sukat_dtls_server_to_string(sukat_dtls_server_t *ctx, char *buf,
                                  size_t buf_len)
{
  struct sockaddr_storage saddr = {};
  socklen_t slen = sizeof(saddr);

  if (sukat_dtls_getsockname(ctx, &saddr, &slen))
    {
      return sukat_util_storage_print((struct sockaddr *)&saddr, buf, buf_len);
    }
  return NULL;
}

bool sukat_dtls_client_ready_for_data(sukat_dtls_client_t *client)
{
  DBG("Client %p: %s", client,
      (client->dtls_finished)
        ? "DTLS unfinished"
        : ((!client->handshake_finished) ? "Handshake not finished"
                                         : "Finished"));
  return (client->dtls_finished && client->handshake_finished);
}

int sukat_dtls_client_fd(sukat_dtls_client_t *client)
{
  if (client)
    {
      return BIO_get_fd(SSL_get_rbio(client->ssl), NULL);
    }
  return -1;
}

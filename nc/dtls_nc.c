#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ctype.h>
#include <assert.h>
#include <signal.h>
#include <string.h>
#include <sys/signalfd.h>

#define LOG_DESCRIPTION "dtls_nc"

#include "sukat_dtls.h"
#include "sukat_log_internal.h"
#include "sukat_epoll.h"
#include "sukat_util.h"
#include "sukat_list.h"

__attribute__((constructor)) static void dtls_nc_ssl_init(void)
{
  sukat_ssl_init();
}

__attribute__((destructor)) static void dtls_nc_ssl_close(void)
{
  sukat_ssl_cleanup();
}

/** @brief Entry for each connected client. */
struct nc_client_entry
{
  sukat_list_link_t link;           //!< Attaches to list.
  sukat_dtls_client_t *client; //!< Client context spawned from server_ctx
};

/** @brief Main context for DTLS netcat. */
struct nc_dtls_ctx
{
  union
  {
    sukat_dtls_server_t *server_ctx; //!< If != NULL, Running in listen mode.
    sukat_dtls_client_t *client_ctx; //!< If != NULL, Running in client mode.
  };
  union
  {
    struct sockaddr_storage address; //!< Listen or connect address.
    struct sockaddr_in address4;
    struct sockaddr_in6 address6;
  };
  socklen_t addr_len;   //!< Length of data in \p address.
  SSL_CTX *ssl_ctx;     //!< SSL_CTX for client or server.
  char *certificate;    //!< Used certificate as path.
  char *pkey;           //!< Used private key as path.
  sukat_list_t clients; //!< List of clients.
  int efd;              //!< Epoll for stdin/dtls.
  int signalfd;         //!< FD for signals.
  bool server;          //!< If context is for server or client.
  bool gdb_run;         //!< Running under gdb.
};

static void usage(const char *bin)
{
  fprintf(stdout,
          "Netcat on DTLS\n"
          "Usage: %s [<opts>] <destination> <port>\n"
          "Options:\n"
          "  --verbose, -v      Increase verbosity.\n"
          "  --cert, -c         Certificate to use.\n"
          "  --pkey, -k         Private key to use.\n"
          "  --gdb, -g          Allow running in gdb (not reg sigint).\n"
          "  --listen, -l       Listen for connections.\n",
          bin);
  exit(EXIT_FAILURE);
}

SSL_CTX *dtls_nc_init_ssl_ctx(struct nc_dtls_ctx *ctx)
{
  struct sukat_cert_options cert = {};
  struct sukat_cert_init_options opts = { };

  if (ctx->certificate)
    {
      opts.cert = &cert;
      cert.cert.data_as_path_to_file = true;
      cert.cert.form = SSL_FILETYPE_PEM;
      cert.cert.path = ctx->certificate;
      if (ctx->pkey)
        {
          cert.pkey.data_as_path_to_file = true;
          cert.pkey.form = SSL_FILETYPE_PEM;
          cert.pkey.path = ctx->pkey;
        }
    }


  opts.method = (ctx->server) ? DTLSv1_2_server_method() : DTLSv1_2_client_method();

  opts.context = ctx;

  return sukat_cert_context_init(&opts);
}

static bool nc_dtls_stdin_reg(struct nc_dtls_ctx *ctx, uint32_t events)
{
  union epoll_data edata =
    {
      .fd = STDIN_FILENO,
    };
  bool bret = sukat_epoll_reg(ctx->efd, STDIN_FILENO, &edata, events);

  if (!bret)
    {
      ERR("Failed to register %d to efd %d with events %x: %s", STDIN_FILENO,
          ctx->efd, events, strerror(errno));
    }
  return bret;
}

static void nc_peer_disconnect(struct nc_dtls_ctx *ctx,
                               struct nc_client_entry *client)
{
  sukat_list_remove(&ctx->clients, &client->link);
  sukat_dtls_client_destroy(ctx->server_ctx, client->client);
  free(client);
}

static int nc_client_read(sukat_dtls_client_t *client)
{
  char buf[BUFSIZ];
  int ret;

  do
    {
      ret = sukat_dtls_client_read(client, (uint8_t *)buf, sizeof(buf));
      if (ret > 0)
        {
          fprintf(stdout, "%.*s", ret, buf);
        }
    } while (ret > 0);
  if (!(ret == -1 &&
        (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)))
    {
      ERR("Failed to read from client: %s", strerror(errno));
      return -1;
    }
  return 0;
}

static void nc_dtls_event_cb(void *context, sukat_dtls_client_t *client,
                             sukat_dtls_client_event_t event)
{
  struct nc_dtls_ctx *ctx = context;
  char ipstr[IPSTRLEN];

  DBG("Event 0x%x on client %p", event, client);

  switch (event)
    {
      case sukat_dtls_client_event_established:
        nc_dtls_stdin_reg(ctx, EPOLLIN);
        /* fall through */
      case sukat_dtls_client_event_connected:
        /* fall through */
      case sukat_dtls_client_event_disconnected:
        INF(
          "Client %s from: %s",
          (event == sukat_dtls_client_event_connected)
            ? "connected"
            : ((event == sukat_dtls_client_event_established) ? "established"
                                                              : "disconnected"),
          sukat_dtls_client_to_string(client, ipstr, sizeof(ipstr)));
        break;
      case sukat_dtls_client_event_data_readable:
        if (nc_client_read(client) == -1)
          {
            sukat_list_link_t *iter;

            // Need to find client to disconnect.
            for (iter = sukat_list_begin(&ctx->clients); iter;
                 iter = sukat_list_next(iter))
              {
                struct nc_client_entry *entry = sukat_list_data(iter, struct nc_client_entry, link);

                if (entry->client)
                  {
                    nc_peer_disconnect(ctx, entry);
                    return;
                  }
              }
            assert(iter);
          }
        break;
      default:
        abort();
        break;
    }
  if (event == sukat_dtls_client_event_disconnected)
    {
      sukat_dtls_client_destroy(ctx->server_ctx, client);
    }
  else if (event == sukat_dtls_client_event_connected)
    {
      struct nc_client_entry *client_entry;

      client_entry = calloc(1, sizeof(*client_entry));
      if (client_entry)
        {
          client_entry->client = client;
          sukat_list_add_to_tail(&ctx->clients, &client_entry->link);
        }
      else
        {
          ERR("Couldn't allocate memory for new client: %s", strerror(errno));
          sukat_dtls_client_destroy(ctx->server_ctx, client);
        }
    }
}

static bool nc_dtls_init_server_or_client(struct nc_dtls_ctx *ctx,
                                          const char *dst, const char *port)
{
  int ret;
  uint32_t events = EPOLLIN;
  struct sukat_dtls_server_options opts = {
    .ssl_ctx = ctx->ssl_ctx,
    .host = dst,
    .port = port,
    .context = ctx,
    .cbs = {.event_cb = nc_dtls_event_cb},
    .subscribed_events = sukat_dtls_client_event_connected |
                         sukat_dtls_client_event_established |
                         sukat_dtls_client_event_data_readable |
                         sukat_dtls_client_event_disconnected};

  if ((!ctx->server &&
       (ret = sukat_dtls_client_connect(ctx->ssl_ctx, dst, port,
                                        &ctx->client_ctx, &events)) >= 0) ||
      (ctx->server && (ctx->server_ctx = sukat_dtls_server_init(&opts))))

    {
      DBG("Created %s context %p", (ctx->server) ? "server" : "client",
          ctx->client_ctx);
      int fd_to_reg = (ctx->server) ? sukat_dtls_server_efd(ctx->server_ctx)
                                    : sukat_dtls_client_fd(ctx->client_ctx);
      union epoll_data edata = { .fd = fd_to_reg };

      if (sukat_epoll_reg(ctx->efd, fd_to_reg, &edata, events))
        {
          DBG("Created DLTS %s context", (ctx->server) ? "server" : "client");
          return true;
        }
      else
        {
          ERR("Failed to register %d to %d: %s", fd_to_reg, ctx->efd,
              strerror(errno));
        }
      if (ctx->server)
        {
          sukat_dtls_server_destroy(ctx->server_ctx);
        }
      else
        {
          sukat_dtls_client_destroy(NULL, ctx->client_ctx);
        }
      ctx->server_ctx = NULL;
    }
  else
    {
      ERR("Failed to initialize %s", (ctx->server) ? "server" : "client");
    }
  return false;
}

int nc_signal_init(struct nc_dtls_ctx *ctx)
{
  sigset_t sigs, oldsigs;

  sigemptyset(&sigs);
  sigemptyset(&oldsigs);
  sigaddset(&sigs, SIGTERM);
  sigaddset(&sigs, SIGPIPE);
  if (!ctx->gdb_run)
    {
      sigaddset(&sigs, SIGINT);
    }
  if (!sigprocmask(SIG_BLOCK, &sigs, &oldsigs))
    {
      int fd = signalfd(-1, &sigs, SFD_NONBLOCK | SFD_CLOEXEC);

      if (fd != -1)
        {
          union epoll_data edata =
            {
              .fd = fd
            };

          DBG("Create signalfd: %d", fd);
          if (sukat_epoll_reg(ctx->efd, fd, &edata, EPOLLIN))
            {
              return fd;
            }
          else
            {
              ERR("Failed to register %d to %d: %s", fd, ctx->efd,
                  strerror(errno));
            }
          sukat_util_fd_safe_close(&fd);
        }
      else
        {
          ERR("Failed to create signalfd: %s", strerror(errno));
        }
      sigprocmask(SIG_SETMASK, &oldsigs, NULL);
    }
  else
    {
      ERR("Failed to block sigs: %s", strerror(errno));
    }
  return -1;
}

static int nc_signal_read(struct nc_dtls_ctx *ctx)
{
  struct signalfd_siginfo sinfo;
  int ret;

  while ((ret = read(ctx->signalfd, &sinfo, sizeof(sinfo))) > 0)
    {
      DBG("Received signal %s from %d", strsignal(sinfo.ssi_signo),
          sinfo.ssi_pid);
      if (sinfo.ssi_signo == SIGTERM || sinfo.ssi_signo == SIGINT)
        {
          INF("Terminated with %s by %d", strsignal(sinfo.ssi_signo),
              sinfo.ssi_pid);
          return 1;
        }
      else if (sinfo.ssi_signo == SIGPIPE)
        {
          DBG("Got sigpipe!");
        }
      else
        {
          ERR("Unknown signal %s from %d", strsignal(sinfo.ssi_signo),
              sinfo.ssi_pid);
          return -1;
        }
    }
  if (ret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
    {
      return 0;
    }
  ERR("Failed to read signalfd %d: %s", ctx->signalfd,
      (!ret) ? "Closed" : strerror(errno));
  return -1;
}

static int nc_write_to_peer(struct nc_dtls_ctx *ctx,
                            sukat_dtls_client_t *client, const char *buf,
                            size_t bytes)
{
  int ret = 0;
  char ipstr[IPSTRLEN];

  DBG_SPAM("Writing %zu bytes to client %s", bytes,
           sukat_dtls_client_to_string(client, ipstr, sizeof(ipstr)));
  if (sukat_dtls_client_ready_for_data(client))
    {
      ret = sukat_dtls_client_write(client, (const uint8_t *)buf, bytes);
      if (ret > 0)
        {
          if (ret != (int)bytes)
            {
              ERR("Wrote only %d bytes of %zu to client %s", ret, bytes,
                  sukat_dtls_client_to_string(client, ipstr, sizeof(ipstr)));
            }
          ret = 0;
        }
      else if (ret == -1 &&
               (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
        {
          DBG("Client %p %s", client,
              (errno == EINTR) ? "interrupted" : "blocked");
        }
      else
        {
          ERR("Client %p %s", client,
              (!ret) ? "Disconnected" : strerror(errno));
          ret = -1;
        }
    }
  else
    {
      if (ctx->server)
        {
          DBG("Will not yet write to client %p, connection not ready",
              client);
        }
      else
        {
          ERR("Trying to write to server, when connection not ready");
          ret = -1;
        }
    }
  return ret;
}

static int nc_write_to_peers(struct nc_dtls_ctx *ctx, const char *buf,
                             size_t bytes)
{
  int ret = -1;

  if (ctx->server)
    {
      if (!sukat_list_begin(&ctx->clients))
        {
          ERR("Server with data from stdin, but no clients");
        }
      else
        {
          sukat_list_link_t *iter;
          ret = 0;

          for (iter = sukat_list_begin(&ctx->clients); iter;
               iter = sukat_list_next(iter))
            {
              struct nc_client_entry *entry =
                sukat_list_data(iter, struct nc_client_entry, link);

              if (nc_write_to_peer(ctx, entry->client, buf, bytes))
                {
                  nc_peer_disconnect(ctx, entry);
                }
            }
        }
    }
  else
    {
      ret = nc_write_to_peer(ctx, ctx->client_ctx, buf, bytes);
    }
  return ret;
}

static int nc_read_stdin(struct nc_dtls_ctx *ctx)
{
  char buf[BUFSIZ];
  int ret;

  // fread y u not werk?!?!!
  ret = read(STDIN_FILENO, buf, sizeof(buf));
  DBG_SPAM("Read %d from %d", ret, STDIN_FILENO);
  if (ret > 0)
    {
      ret = nc_write_to_peers(ctx, buf, ret);
    }
  else if (ret == -1 && (errno == EINTR))
    {
      DBG("Interrupted while reading stdin");
      ret = 0;
    }
  else
    {
      ERR("Failed to read stdin: %s", (!ret) ? "closed" : strerror(errno));
      ret = -1;
    }
  return ret;
}

/** This is the beef! */
static int nc_epoll_cb(void *context, uint32_t events, union epoll_data *data)
{
  struct nc_dtls_ctx *ctx = context;
  int ret = -1;

  DBG("Events %x with fd %d", events, data->fd);

  if (data->fd == ctx->signalfd)
    {
      DBG_SPAM("Data from signal");
      ret = nc_signal_read(ctx);
    }
  else if (data->fd == STDIN_FILENO)
    {
      DBG_SPAM("Data from stdin");
      ret = nc_read_stdin(ctx);
    }
  else if (ctx->server && (data->fd == sukat_dtls_server_efd(ctx->server_ctx)))
    {
      DBG_SPAM("Data to server");
      ret = sukat_dtls_server_process(ctx->server_ctx, 0);
    }
  else if (!ctx->server && (data->fd == sukat_dtls_client_fd(ctx->client_ctx)))
    {
      DBG_SPAM("Data from server");
      if (sukat_dtls_client_ready_for_data(ctx->client_ctx))
        {
          ret = nc_client_read(ctx->client_ctx);
        }
      else
        {
          uint32_t events = EPOLLIN;
          int fd = sukat_dtls_client_fd(ctx->client_ctx);

          sukat_epoll_remove(ctx->efd, fd);
          ret = sukat_dtls_client_connect(NULL, NULL, NULL, &ctx->client_ctx,
                                          &events);
          if (ret >= 0)
            {
              union epoll_data edata =
                {
                  .fd = fd
                };

              if (ret == 1 && !nc_dtls_stdin_reg(ctx, EPOLLIN))
                {
                  ERR("Failed to register stdin");
                  ret = -1;
                }
              else if ((sukat_epoll_reg(ctx->efd, fd, &edata, events)))
                {
                  ret = 0;
                }
              else
                {
                  ERR("Failed to register %d to %d: %s", fd, ctx->efd,
                      strerror(errno));
                  ret = -1;
                }
            }
          else
            {
              ERR("Failed to continue connecting to server");
            }
        }
    }
  else
    {
      ERR("Unknown fd %d in event loop!", data->fd);
      abort();
    }

  return ret;
}

int main(int argc, char **argv)
{
  struct nc_dtls_ctx ctx = { };
  int cookie_index = -1;
  struct sukat_log_ctx log_ctx =
    {
      .lvl = SUKAT_LOG_NONE,
      .context = &ctx,
      .log_cb = sukat_log_std
    };
  int c, exit_ret = EXIT_FAILURE;
  char *dst = NULL, *port = NULL;
  struct option long_opts[]=
    {
        {"source", required_argument, 0, 's'},
        {"certificate", required_argument, 0, 'c'},
        {"pkey", required_argument, 0, 'k'},
        {"ifindex", required_argument, 0, 'i'},
        {"listen", no_argument, 0, 'l'},
        {"verbose", no_argument, 0, 'v'},
        {"gdb", no_argument, 0, 'g'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

  // Start off with IPV6 address.
  ctx.address.ss_family = AF_INET6;

  while ((c = getopt_long(argc, argv, "s:i:c:k:lvhg", long_opts, NULL)) != -1)
    {
      switch (c)
        {
        case 'c':
          ctx.certificate = optarg;
          break;
        case 'k':
          ctx.pkey = optarg;
          break;
        case 'i':
          break;
        case 'g':
          ctx.gdb_run = true;
          break;
        case 'l':
          ctx.server = true;
          break;
        case 'v':
          log_ctx.lvl++;
          break;
        default:
        case 'h':
          usage(argv[0]);
          break;
        }
    }

  sukat_log_global_ctx(&log_ctx);

  if (optind < argc)
    {
      while (optind < argc)
        {
          size_t arg_len = strlen(argv[optind]);
          unsigned int i;
          char *str = argv[optind];

          // Test if it's a port.
          if (arg_len <= strlen("65535") && !({
                bool nondigit = false;

                // Lambda in C oh my..
                for (i = 0; i < arg_len; i++)
                  {
                    nondigit |= !isdigit(str[i]);
                  }
                nondigit;
              }))
            {
              port = str;
            }
          else
            {
              dst = str;
            }
          optind++;
        }
    }
  if (!ctx.server && (!dst || !port))
    {
      ERR("dst: %s, port %s. Need both for client connection", dst, port);
      usage(argv[0]);
      return EXIT_FAILURE;
    }

  ctx.efd = epoll_create1(EPOLL_CLOEXEC);
  if (ctx.efd != -1)
    {
      if (!ctx.server || (cookie_index = sukat_cert_cookie_index_init(32)) >= 0)
        {
          ctx.ssl_ctx = dtls_nc_init_ssl_ctx(&ctx);

          if (ctx.ssl_ctx)
            {
              if (nc_dtls_init_server_or_client(&ctx, dst, port))
                {
                  if (ctx.server)
                    {
                      char ipstr[IPSTRLEN];

                      INF("Hosting at: %s",
                          sukat_dtls_server_to_string(ctx.server_ctx, ipstr,
                                                      sizeof(ipstr)));
                    }
                  else
                    {
                      char ipstr[IPSTRLEN];

                      INF("Connecting to: %s",
                          sukat_dtls_client_to_string(ctx.client_ctx, ipstr,
                                                      sizeof(ipstr)));
                    }
                  ctx.signalfd = nc_signal_init(&ctx);

                  if (ctx.signalfd != -1)
                    {
                      exit_ret = EXIT_SUCCESS;
                      assert(!ctx.clients.head);
                      assert(!ctx.clients.tail);
                      while (!sukat_epoll_wait(ctx.efd, nc_epoll_cb, &ctx, -1))
                        {
                          // Main loop'd
                        }
                      sukat_util_fd_safe_close(&ctx.signalfd);
                    }
                  fclose(stdin);
                  if (ctx.server)
                    {
                      sukat_list_link_t *iter;

                      while ((iter = sukat_list_begin(&ctx.clients)))
                        {
                          struct nc_client_entry *client_entry=
                            sukat_list_data(iter, struct nc_client_entry, link);

                          sukat_dtls_client_destroy(ctx.server_ctx,
                                                    client_entry->client);
                          sukat_list_remove(&ctx.clients, &client_entry->link);
                          free(client_entry);
                        }
                      sukat_dtls_server_destroy(ctx.server_ctx);
                    }
                  else
                    {
                      sukat_dtls_client_destroy(NULL, ctx.client_ctx);
                    }
                }
              SSL_CTX_free(ctx.ssl_ctx);
            }
          else
            {
              ERR("Failed to initialize SSL context");
            }
          if (cookie_index != -1)
            {
              sukat_cert_cookie_index_close(cookie_index);
            }
        }
      else
        {
          ERR("Failed to initialize cookie exchange for server");
        }
      sukat_util_fd_safe_close(&ctx.efd);
    }
  else
    {
      ERR("Failed to create epoll: %s", strerror(errno));
    }
  fclose(stdout);

  return exit_ret;
}

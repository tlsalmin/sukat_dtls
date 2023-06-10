#include <gtest/gtest.h>

extern "C"{
#include "sukat_dtls.h"
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "sukat_util.h"
#include "sukat_log.h"
#include "sukat_epoll.h"

__attribute__((constructor)) static void init_log(void)
  {
    static struct sukat_log_ctx log_ctx =
      {
        .log_cb = sukat_log_std,
        .context = NULL,
        .lvl = SUKAT_LOG_DEBUG_SPAM
      };

    if (true)
      {
        sukat_log_global_ctx(&log_ctx);
      }
  }
}

class sukatDTLSTest : public ::testing::Test
{
protected:

  static void SetUpTestCase()
    {
      sukat_ssl_init();
      cookie_index = sukat_cert_cookie_index_init(0);
      ASSERT_NE(-1, cookie_index);
    }

  static void TearDownTestCase()
    {
      sukat_cert_cookie_index_close(cookie_index);
    }

  bool prep_timeout()
  {
      tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);

      if (tfd != -1)
      {
          struct itimerspec tspec =
          {
              .it_interval =
              {
                  .tv_sec = 10,
                  .tv_nsec = 0
              },
              .it_value = {
                  .tv_sec = 10,
                  .tv_nsec = 0,
              }
          };

          if (!timerfd_settime(tfd, 0, &tspec, NULL))
          {
              union epoll_data edata = {.fd = tfd};

              if (sukat_epoll_reg(efd, tfd, &edata, EPOLLIN))
              {
                  return true;
              }
          }
          else
          {
              abort();
          }
          close(tfd);
      }
      else
      {
          abort();
      }
      return false;
  }

  virtual void SetUp()
    {
      bool bret;
      char buf[INET6_ADDRSTRLEN];
      struct sukat_cert_options cert_opts = { };
      struct sukat_cert_init_options cert_init_opts = { };
      struct sukat_dtls_server_options server_opts = { };
      std::string cert_path(CERT_PATH), pkey_path(CERT_PATH);
      union epoll_data edata = {};
      struct sockaddr_storage server_saddr;
      struct sockaddr_in6 *sin6 =
        reinterpret_cast<struct sockaddr_in6 *>(&server_saddr);
      struct sockaddr_in *sin4 =
        reinterpret_cast<struct sockaddr_in *>(&server_saddr);
      int port;
      void *addr;

      client_handshake_finished = 0;
      cert_path += "/server_cert.pem";
      pkey_path += "/server_key.pem";
      cert_init_opts.cert = &cert_opts;
      cert_opts.cert.path = cert_path.c_str();
      cert_opts.pkey.path = pkey_path.c_str();
      cert_opts.cert.data_as_path_to_file =
        cert_opts.pkey.data_as_path_to_file = true;
      cert_opts.cert.form = cert_opts.pkey.form = SSL_FILETYPE_PEM;
      cert_init_opts.method = DTLS_server_method();
      cert_init_opts.context = this;

      ssl_ctx = sukat_cert_context_init(&cert_init_opts);
      ASSERT_NE(nullptr, ssl_ctx);

      server_opts.ssl_ctx = ssl_ctx;
      server_opts.context = this;
      server_opts.cbs.event_cb = dtls_event_cb;
      server_opts.subscribed_events =
        static_cast<sukat_dtls_client_event_t>(0xff);

      server_ctx = sukat_dtls_server_init(&server_opts);
      ASSERT_NE(nullptr, server_ctx);

      // Solve the server port.
      memset(&server_saddr, 0, sizeof(server_saddr));
      server_addr_len = sizeof(server_saddr);
      bret =
        sukat_dtls_getsockname(server_ctx, &server_saddr, &server_addr_len);
      ASSERT_EQ(true, bret);
      if (server_saddr.ss_family == AF_INET6)
        {
          port = ntohs(sin6->sin6_port);
          addr = &sin6->sin6_addr;
        }
      else
        {
          port = ntohs(sin4->sin_port);
          addr = &sin4->sin_addr;
        }
      server_port = std::to_string(port);
      server_addr = std::string(inet_ntop(server_saddr.ss_family, addr,
                                          buf, sizeof(buf)));

      efd = epoll_create1(EPOLL_CLOEXEC);
      ASSERT_NE(-1, efd);

      edata.fd = sukat_dtls_server_efd(server_ctx);
      bret = sukat_epoll_reg(efd, sukat_dtls_server_efd(server_ctx), &edata,
                             EPOLLIN);
      ASSERT_NE(false, bret);

      bret = prep_timeout();
      ASSERT_EQ(true, bret);
    }
  virtual void TearDown()
    {
      sukat_dtls_server_destroy(server_ctx);
      SSL_CTX_free(ssl_ctx);
      sukat_util_fd_safe_close(&efd);
      sukat_util_fd_safe_close(&tfd);
    }
  static void dtls_event_cb(void *context, sukat_dtls_client_t *client,
                            sukat_dtls_client_event_t event)
    {
      sukatDTLSTest *test_ctx = static_cast<sukatDTLSTest *>(context);
      uint8_t buf[BUFSIZ];

      test_ctx->events_received = event;
      if (event == sukat_dtls_client_event_established)
        {
          test_ctx->last_client_connected = client;
        }
      else if (event == sukat_dtls_client_event_data_readable)
        {
          int ret = sukat_dtls_client_read(client, buf, sizeof(buf));

          if (ret > 0)
            {
              // First if you don't succeed, try reinterpret cast.
              test_ctx->last_data.append(reinterpret_cast<char*>(buf), ret);
            }
          else if (errno != EAGAIN && errno != EWOULDBLOCK)
            {
              sukat_dtls_client_destroy(test_ctx->server_ctx, client);
            }
        }
    }

  static int test_sukat_epoll(void *context,
                              __attribute__((unused)) uint32_t events,
                              union epoll_data *data)
    {
      sukatDTLSTest *test_ctx = static_cast<sukatDTLSTest *>(context);
      int ret = -1;
      char buf[BUFSIZ];

      if (data->fd == sukat_dtls_server_efd(test_ctx->server_ctx))
        {
          ret = sukat_dtls_server_process(test_ctx->server_ctx, 0);
          EXPECT_NE(-1, ret);
        }
      else if (data->fd == test_ctx->tfd)
      {
          fprintf(stderr, "Timeout triggered\n");
          return -1;
      }
      else
        {
          sukat_dtls_client_t *client_ctx =
            static_cast<sukat_dtls_client_t *>(data->ptr);

          // Can't assert in static func? K.
          EXPECT_NE(nullptr, client_ctx);
          if (!client_ctx)
          {
              abort();
          }
          if (!sukat_dtls_client_ready_for_data(client_ctx))
            {
              uint32_t events;

              printf("Connecting client\n");
              ret = sukat_dtls_client_connect(NULL, NULL, 0,
                                              &client_ctx, &events);
              if (ret >= 0)
                {
                  bool bret;
                  int fd = sukat_dtls_client_fd(client_ctx);
                  union epoll_data edata =
                    {
                      .ptr = client_ctx
                    };
                  std::cout
                    << "Listening for " << reinterpret_cast<void *>(client_ctx)
                    << " with events " << std::to_string(events) << std::endl;

                  bret =
                    sukat_epoll_reg(test_ctx->efd, fd, &edata, events);
                  EXPECT_TRUE(bret);

                  if (ret == 1)
                    {
                        printf("Client handshake finished\n");
                      test_ctx->client_handshake_finished++;
                    }
                }
              else
              {
                ADD_FAILURE() << "Failed to connect on client "
                              << reinterpret_cast<void *>(client_ctx);
              }
            }
          else
            {
              ret = sukat_dtls_client_read(
                client_ctx, reinterpret_cast<uint8_t *>(buf), sizeof(buf));
              if (ret > 0)
                {
                  test_ctx->last_data_from_server.append(buf, ret);
                }
            }
        }
      return ret;
    }

  sukat_dtls_server_t *server_ctx;
  SSL_CTX *ssl_ctx;
  static int cookie_index;
  sukat_dtls_client_event_t events_received;
  socklen_t server_addr_len;
  int efd{-1}, tfd{-1}; //!< Event fd to use.
  unsigned client_handshake_finished;
  std::string last_data, last_data_from_server;
  sukat_dtls_client_t *last_client_connected;
  std::string server_port, server_addr;
};

int sukatDTLSTest::cookie_index = -1;

TEST_F(sukatDTLSTest, testClient)
{
  int ret;
  bool bret;
  SSL_CTX *client_ssl_ctx;
  uint32_t client_fd_events = 0;
  int fd;
  union epoll_data edata;
  sukat_dtls_client_t *client_ctx = NULL;
  std::string hello("Hello from client"),
    reply("Hello from server"), received_reply;
  char buf[BUFSIZ];

  client_ssl_ctx = SSL_CTX_new(DTLS_client_method());
  ASSERT_NE(nullptr, client_ssl_ctx);

  ret = sukat_dtls_client_connect(client_ssl_ctx, server_addr.c_str(),
                                  server_port.c_str(),
                                  &client_ctx, &client_fd_events);
  EXPECT_NE(-1, ret);
  ASSERT_NE(nullptr, client_ctx);


  fd = sukat_dtls_client_fd(client_ctx);
  printf("Adding fd %d to epoll %d with events %u\n", fd, efd, client_fd_events);
  edata.ptr = client_ctx;
  bret = sukat_epoll_reg(efd, fd, &edata, client_fd_events);
  EXPECT_TRUE(bret);

  ret = 0;
  while (!client_handshake_finished && ret != -1)
    {
      ret = sukat_epoll_wait(efd, test_sukat_epoll, this, -1);
    }
  EXPECT_NE(-1, ret);

  // Lets write something to server.
  ret = sukat_dtls_client_write(
    client_ctx, reinterpret_cast<const uint8_t *>(hello.c_str()),
    hello.length());
  EXPECT_LT(0, ret);

  ret = sukat_epoll_wait(efd, test_sukat_epoll, this, -1);
  EXPECT_NE(-1, ret);

  EXPECT_EQ(hello, last_data);

  ret = sukat_dtls_client_write(last_client_connected,
                                reinterpret_cast<const uint8_t*>(reply.c_str()),
                                reply.length());
  EXPECT_LT(0, ret);

  ret = sukat_dtls_client_read(client_ctx, reinterpret_cast<uint8_t *>(buf),
                               sizeof(buf));
  EXPECT_LT(0, ret);

  received_reply.append(buf, ret);
  EXPECT_EQ(received_reply, reply);

  sukat_epoll_remove(efd, fd);
  sukat_dtls_client_destroy(NULL, client_ctx);
  client_ctx = nullptr;

  ret = sukat_epoll_wait(efd, test_sukat_epoll, this, -1);
  EXPECT_NE(-1, ret);

  // Make a new connection and ensure the client recovers from the first.
  client_handshake_finished = 0;

  ret = sukat_dtls_client_connect(client_ssl_ctx, server_addr.c_str(),
                                  server_port.c_str(),
                                  &client_ctx, &client_fd_events);
  EXPECT_NE(-1, ret);
  ASSERT_NE(nullptr, client_ctx);

  fd = sukat_dtls_client_fd(client_ctx);
  edata.ptr = client_ctx;
  bret = sukat_epoll_reg(efd, fd, &edata, client_fd_events);
  EXPECT_TRUE(bret);

  ret = 0;
  while (!client_handshake_finished && ret != -1)
    {
      ret = sukat_epoll_wait(efd, test_sukat_epoll, this, -1);
    }
  EXPECT_NE(-1, ret);

  last_data.clear();

  // Lets write something to server.
  ret = sukat_dtls_client_write(
    client_ctx, reinterpret_cast<const uint8_t *>(hello.c_str()),
    hello.length());
  EXPECT_LT(0, ret);

  ret = sukat_epoll_wait(efd, test_sukat_epoll, this, -1);
  EXPECT_NE(-1, ret);

  EXPECT_EQ(hello, last_data);

  sukat_dtls_client_destroy(NULL, client_ctx);
  client_ctx = nullptr;

  SSL_CTX_free(client_ssl_ctx);

  ret = sukat_epoll_wait(efd, test_sukat_epoll, this, -1);
  EXPECT_NE(-1, ret);
}

TEST_F(sukatDTLSTest, testManyClients)
{

  int ret;
  const unsigned n_clients = 20;
  bool bret;
  int fd;
  union epoll_data edata;
  std::vector<std::pair<SSL_CTX *, sukat_dtls_client_t *>> client_vec;
  std::string hello("Hello from client"), reply("Hello from server"),
    received_reply;
  char buf[BUFSIZ];

  for (unsigned i = 0; i < n_clients; i++)
    {
      SSL_CTX *client_ssl_ctx;

      sukat_dtls_client_t *client_ctx = nullptr;
      uint32_t client_fd_events = 0;

      client_ssl_ctx = SSL_CTX_new(DTLS_client_method());
      ASSERT_NE(nullptr, client_ssl_ctx);

      std::cout << "Connecting client " << std::to_string(i) << std::endl;

      ret = sukat_dtls_client_connect(client_ssl_ctx, server_addr.c_str(),
                                      server_port.c_str(), &client_ctx,
                                      &client_fd_events);
      EXPECT_NE(-1, ret);
      ASSERT_NE(nullptr, client_ctx);

      std::cout << "Registering client for epoll handling on client "
                << reinterpret_cast<void *>(client_ctx) << std::endl;

      client_vec.emplace_back(std::make_pair(client_ssl_ctx, client_ctx));

      fd = sukat_dtls_client_fd(client_ctx);
      printf("Adding fd %d to epoll %d with events %u\n", fd, efd,
             client_fd_events);
      edata.ptr = client_ctx;
      bret = sukat_epoll_reg(efd, fd, &edata, client_fd_events);
      EXPECT_TRUE(bret);
    }

  ret = 0;
  while (client_handshake_finished < n_clients && ret != -1)
    {
      ret = sukat_epoll_wait(efd, test_sukat_epoll, this, -1);
      std::cout << std::flush;
    }
  EXPECT_NE(-1, ret);
}

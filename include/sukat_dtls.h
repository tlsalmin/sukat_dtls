#pragma once

#include <stdint.h>
#include <sys/socket.h>
#include "sukat_cert.h"
#include "sukat_log.h"

/** @brief DTLS main context. */
typedef struct sukat_dtls_server_context sukat_dtls_server_t;

/** @brief DTLS client context */
typedef struct sukat_dtls_client_context sukat_dtls_client_t;

/** @brief Events invoked for DTLS clients. */
typedef enum sukat_dtls_client_event
{
  sukat_dtls_client_event_connected = 0x01,   //!< New client connected.
  //!< New client DTLS accepted. Data can be written only after this event.
  sukat_dtls_client_event_established = 0x02,
  sukat_dtls_client_event_data_readable = 0x04, //!< Client has data readable.
  //TODO might not need disconnect event.
  sukat_dtls_client_event_disconnected = 0x08 //!< Client disconnected.
} sukat_dtls_client_event_t;
/**
 * @brief Callback invoked when clients have state changing events.
 *
 * @param context       Caller context.
 * @param client        Opaque client context.
 * @param event         Events active for client.
 */
typedef void (*sukat_dtls_client_event_cb)(void *context,
                                           sukat_dtls_client_t *client,
                                           sukat_dtls_client_event_t event);

/** @brief Event callbacks invoked by library */
struct sukat_dtls_server_cbs
{
  sukat_dtls_client_event_cb event_cb; //!< Called per client event.
};

struct sukat_dtls_server_options
{
  SSL_CTX *ssl_ctx; //!< DTLS SSL_CTX to use.
  const char *host; //!< End-point to which should be bound to.
  const char *port; //!< Port to which server clients from.
  void *context;    //!< Context given to user callbacks.
  struct sukat_dtls_server_cbs cbs; //!< Callbacks invoked by library.
  sukat_dtls_client_event_t subscribed_events; /**!< Bitmap of events caller
                                                     is interested in. */
};

/**
 * @brief Initialize and start DTLS server context.
 *
 * From the options, only the cert_opts->cert, cert_opts->pkey are mandatory.
 *
 * @param opts  Options for end-point.
 *
 * @return == NULL      Failure.
 * @return != NULL      Success.
 */
sukat_dtls_server_t *sukat_dtls_server_init(
  struct sukat_dtls_server_options *opts);

/**
 * @brief Fetches an unique peer identifier for this client.
 *
 * @param client        Client.
 * @param slen          Length of peer identifier.
 *
 * @return == Pointer to peer identifier data.
 */
struct sockaddr *sukat_dtls_client_get_peer(sukat_dtls_client_t *client,
                                            socklen_t *slen);

/**
 * @brief Prints \p client peering information to buffer.
 *
 * @param client        Client to print.
 * @param buf           Buffer to print to.
 * @param buf_len       Length of buffer. Use at least IPSTRLEN
 *
 * @return      \p buf.
 */
char *sukat_dtls_client_to_string(sukat_dtls_client_t *client, char *buf,
                                  size_t buf_len);

/**
 * @brief Fetches the SSL context for \p client.
 *
 * Usage hint: sukat_dtls doesn't set it's own context to \p ssl, so it's
 *             freely usable by the caller.
 *
 * @param client DTLS client.
 *
 * @return SSL context of client.
 */
SSL *sukat_dtls_client_get_ssl(sukat_dtls_client_t *client);

/**
 * @brief Returns the event loop fd for this DTLS context.
 *
 * @param ctx   DTLS context.
 *
 * @return Pollable fd.
 */
int sukat_dtls_server_efd(sukat_dtls_server_t *ctx);

/**
 * @brief Process events from sukat DTLS server.
 *
 * @param ctx   Context for processing.
 *
 * @return < 0  Failure.
 * @return == 0 Success.
 */
int sukat_dtls_server_process(sukat_dtls_server_t *ctx, int timeout);

/**
 * @brief Destroy DTLS server context.
 *
 * @param ctx   Context to destroy
 */
void sukat_dtls_server_destroy(sukat_dtls_server_t *ctx);

/**
 * @brief Read data from client.
 *
 * @param ctx Server context.
 * @param client Client context.
 * @param buf Buffer to read to.
 * @param buf_size Size of \p buf.
 *
 * @return > 0  Data read.
 * @return == 0 Disconnected.
 * @return < 0  Failure. Check errno (including EAGAIN || EWOULDBLOCK).
 */
int sukat_dtls_client_read(sukat_dtls_client_t *client, uint8_t *buf,
                           size_t buf_size);

/**
 * @brief Write data to client.
 *
 * @param ctx           DTLS server context.
 * @param client        Client context.
 * @param buf           Buffer to write.
 * @param buf_len       Length of buffer to write.
 *
 * @return == 0         Disconnected
 * @return > 0          Bytes written.
 * @return < 0  Failure. Check errno (including EAGAIN || EWOULDBLOCK).
 */
int sukat_dtls_client_write(sukat_dtls_client_t *client, const uint8_t *buf,
                            size_t buf_len);

/**
 * @brief Destroy DTLS client \p client.
 *
 * @param ctx           Server context.
 * @param client        client context.
 */
void sukat_dtls_client_destroy(sukat_dtls_server_t *ctx,
                               sukat_dtls_client_t *client);

/**
 * @brief Create or contnue a DTLS connection by connecting to \p server.
 *
 * The fd for this client is fetchable from the SSLs read bio after the first
 * call with this connection. The parameters ssl, dst, port are only used on
 * first call and can be omitted for the later calls.
 *
 * @param ssl           SSL_CTX to use.
 * @param dst           IP or hostname of server.
 * @param port          Port to connect to.
 * @param client        Pointer to client data storage. NULL on first call,
 *                      afterwards the pointer to the previously returned ctx.
 * @param events        Epoll events user should listen to on this client.
 *
 * @return == 1         Connected and handshake finished.
 * @return == 0         OK, but handshake not yet finished.
 * @return != NULL      Connected DTLS client.
 */
int sukat_dtls_client_connect(SSL_CTX *ssl, const char *dst, const char *port,
                              sukat_dtls_client_t **client, uint32_t *events);

/**
 * @brief Query the DTLS server port in host byte order.
 *
 * @param ctx DTLS server context.
 *
 * @return == Server port in host-byte order.
 */
bool sukat_dtls_getsockname(sukat_dtls_server_t *ctx,
                            struct sockaddr_storage *saddr,
                            socklen_t *slen);

/**
 * @brief Stringify server listening address to buffer.
 *
 * @param ctx   Server context.
 * @param buf   Buffer to stringify to.
 * @param buf_len       Length of \p buf.
 *
 * @return buf.
 */
char *sukat_dtls_server_to_string(sukat_dtls_server_t *ctx, char *buf,
                                  size_t buf_len);

/**
 * @brief Checks if client is ready for data transfers.
 *
 * The client needs to complete the DTLS and SSL handshake before application
 * data can be transferred
 *
 * @param client        Client to query
 *
 * @return == true      Client ready for data transfer.
 * @return == false     Client still connecting.
 */
bool sukat_dtls_client_ready_for_data(sukat_dtls_client_t *client);

/**
 * @brief Get fd from client context.
 *
 * @param client        Client to fetch fd from.
 *
 * @return == file descriptor assigned for client.
 */
int sukat_dtls_client_fd(sukat_dtls_client_t *client);

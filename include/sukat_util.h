#pragma once

#include <sys/socket.h>
#include <stdbool.h>

//TODO: This is not only sockopt anymore really..
/** @brief sockopts as a bitmask */
typedef enum sukat_util_fd_opts
{
  sukat_sockopt_reuseaddr = 0x01, //!< Allow reuse of bound address.
  sukat_sockopt_reuseport = 0x02, //!< Allow reuse of bound port.
  sukat_sockopt_bind = 0x04,      //!< Bind the socket.
  sukat_sockopt_v6andv4 = 0x08,   //!< Accept both IPv4 and IPv6.
  sukat_sockopt_numeric = 0x10,   //!< Numeric solve for getaddrinfo.
  sukat_sockopt_connect = 0x20,   //!< Connect the socket.
  sukat_sockopt_nonblock = 0x40,  //!< Non-blocking socket.
  sukat_sockopt_cloexec = 0x80,   //!< Close fd on fork.
} sukat_util_fd_opts_t;

/**
 * @brief Solve a address into \p saddr.
 *
 * @param addr  Optional Address to solve.
 * @param port  Optional port to use.
 * @param type  Type for socket, DGRAM or STREAM.
 * @param saddr Target for solving.
 * @param slen  Length of returned sockaddr data.
 * @param numeric_solve Only accept numeric IP-values. (cut out DNS).
 *
 * @return == true      Success.
 * @return == false     Failure.
 */
bool sukat_util_solve(const char *addr, const char *port,
                      int type, struct sockaddr_storage *saddr,
                      socklen_t *slen, sukat_util_fd_opts_t opts);

/** @brief Enough to hold IPv6 address and port. */
#define IPSTRLEN (INET6_ADDRSTRLEN + 8)

/**
 * @brief Prints a sockaddr storage contained IP+port.
 *
 * @param saddr         Storage to print.
 * @param buf           Buffer to print to.
 * @param buf_len       Length of \p buf.
 *
 * @return == NULL      Failure.
 * @return != NULL      buf.
 */
char *sukat_util_storage_print(struct sockaddr *saddr,
                               char *buf, size_t buf_len);

/**
 * @brief Safely close fd, asserting on non-interrupt failure.
 *
 * @param fd    File descriptor to close and set to -1.
 */
void sukat_util_fd_safe_close(int *fd);

/**
 * @brief Perform a number of sockopts on \p fd.
 *
 * Known sockopts: SO_REUSEADDR, SO_REUSEPORT
 *
 * @param fd    FD to perform on.
 * @param opts  sockopts to perform.
 *
 * @return == true      Success.
 * @return == false     Failure.
 */
bool sukat_util_sockopts(int fd, const sukat_util_fd_opts_t opts);

/**
 * @brief Creates a socket.
 *
 * @param addr  Address to bind to.
 * @param port  Port to bind top.
 * @param type  Socket type.
 * @param opts  Options for socket.
 * @param saddr Optional storage for solved address.
 * @param saddr_len Storage for initial length of \p saddr and eventual solved
 *                  length of data in \p saddr.
 *
 * @return == -1        Failure.
 * @return >= 0         Socket.
 */
int sukat_util_fd_create(const char *addr, const char *port, int type,
                         sukat_util_fd_opts_t opts, struct sockaddr *saddr,
                         socklen_t *saddr_len);

/**
 * @brief Peek the peer queued at \p fd and save the end-point to \p saddr
 *
 * @param fd    FD used for peeking.
 * @param saddr Storage for peer end-point.
 * @param slen  Length of \p saddr.
 *
 * @return <= 0         Failure.
 * @return > 0          Length of peer data in \p saddr.
 */
int sukat_util_peek_peer(int fd, struct sockaddr *saddr, socklen_t slen);

/**
 * @brief Duplicates given bound_fd and connects it to \p peer.
 *
 * @param bound_fd      FD to duplicate.
 * @param type          type for new fd. (socket parameter 2)
 * @param peer          Peaked peer address.
 * @param slen          Length of data in \p peer.
 * @param opts          Options to sockopt on new fd.
 *
 * @return == -1        Failure.
 * @return >= 0         New connected fd, bound to \p bound_fd.
 */
int sukat_util_fd_duplicate(int bound_fd, int type,
                            struct sockaddr_storage *peer,
                            socklen_t slen, sukat_util_fd_opts_t opts);

/**
 * @brief Query if IPv6 is enabled.
 *
 * @return true Enabled.
 * @return false Disabled.
 */
bool sukat_util_ipv6_enabled(void);

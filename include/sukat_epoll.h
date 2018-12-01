#pragma once

/**
 * @brief Light-weight event loop library
 */

#include <sys/epoll.h>
#include <stdbool.h>

/**
 * @brief Register \p fd to \p efd.
 *
 * Can be called on existing fd, where the call is changed to a mod.
 *
 * @param efd           Epoll fd.
 * @param fd            Fd to register.
 * @param data          Data returned when fd active.
 * @param events        Events to listen for.
 *
 * @return == false     Failure.
 * @return == true      Success.
 */
bool sukat_epoll_reg(int efd, int fd, union epoll_data *data, uint32_t events);

/**
 * @brief Remove \p fd from epoll \p efd.
 *
 * @param efd Epoll fd.
 * @param fd  fd to remove.
 *
 * @return == false Failure.
 * @return == true  Success.
 */
bool sukat_epoll_remove(int efd, int fd);

/**
 * @brief Callback invoked on each fd active.
 *
 * @param context        Context given to \p sukat_epoll_wait
 * @param events         Events in fd.
 * @param data           Data registered to fd.
 *
 * @return == 0         Continue to next step.
 * @return != 0         Stop and return this value from wait.
 */
typedef int (*sukat_epoll_cb)(void *context, uint32_t events,
                              union epoll_data *data);

/**
 * @brief Waits for epoll events.
 *
 * @param efd           Epoll fd.
 * @param cb            Callback to invoke per fd.
 * @param context       Context to pass to callback.
 * @param timeout       Timeout to wait for events.
 */
int sukat_epoll_wait(int efd, sukat_epoll_cb cb, void *context, int timeout);

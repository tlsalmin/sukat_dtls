#pragma once

#include <stdarg.h>

/** @brief Log levels for APIs */
typedef enum sukat_log_lvl
{
  SUKAT_LOG_NONE = -1, //!< No logging.
  SUKAT_LOG_ERROR = 0,
  SUKAT_LOG_INFO,
  SUKAT_LOG_DEBUG,
  SUKAT_LOG_DEBUG_SPAM,
} sukat_log_lvl_t;

/**
 * @brief Generic log callback
 *
 * @param lvl           Log level.
 * @param context       User given context.
 * @param component     String describing component.
 * @param func          Function from which log was generated.
 * @param line          Line from which log was generated.
 * @param fmt           Log format.
 * @param ap            va_list of arguments.
 */
typedef void (*sukat_log_cb)(sukat_log_lvl_t lvl, void *context,
                             const char *component,
                             const char *func, unsigned int line,
                             const char *fmt, va_list ap);

/** @brief Log to stdout/stderr. Context is ignored.  */
void sukat_log_std(sukat_log_lvl_t lvl, void *context, const char *component,
                   const char *func, unsigned int line,
                   const char *fmt, va_list ap);

/** @brief Small log context passable to utility functions */
struct sukat_log_ctx
{
  sukat_log_cb log_cb; //!< Callback for logging.
  void *context;   //!< Context for logging callback.
  sukat_log_lvl_t lvl; //!< Log verbosity level.
};

/**
 * @brief Register a global log context.
 *
 * @param ctx   Context.
 */
void sukat_log_global_ctx(struct sukat_log_ctx *ctx);


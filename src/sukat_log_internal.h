#pragma once

#include <string.h>
#include <errno.h>
#include "sukat_log.h"

extern struct sukat_log_ctx sukat_log_glb;

/**
 * @brief Function to use for logging by subcomponents.
 *
 * @param cb            Log callback if set.
 * @param log_lvl       Log level set in options.
 * @param lvl           Log level of this log.
 * @param context       User context.
 * @param component     String describing component
 * @param func          Function from which log is called.
 * @param line          Line from which log is called.
 * @param fmt           Format.
 */
void sukat_log(sukat_log_cb cb, sukat_log_lvl_t lvl,
               void *context, const char *component, const char *func,
               unsigned int line, const char *fmt, ...)
     __attribute__((format(printf, 7, 8)));


#define LOG(_lvl, ...) sukat_log(sukat_log_glb.log_cb, _lvl,                   \
                                 sukat_log_glb.context, LOG_DESCRIPTION,       \
                                 __FUNCTION__, __LINE__, __VA_ARGS__)
#define ERR(...) LOG(SUKAT_LOG_ERROR, __VA_ARGS__)
#define INF(...) LOG(SUKAT_LOG_INFO, __VA_ARGS__)
#define DBG(...) LOG(SUKAT_LOG_DEBUG, __VA_ARGS__)
#define DBG_SPAM(...) LOG(SUKAT_LOG_DEBUG_SPAM, __VA_ARGS__)


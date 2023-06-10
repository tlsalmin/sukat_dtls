#include <stdio.h>

#include "sukat_log_internal.h"

struct sukat_log_ctx sukat_log_glb;

void sukat_log(sukat_log_cb cb, sukat_log_lvl_t lvl,
               void *context, const char *component, const char *func,
               unsigned int line, const char *fmt, ...)
{
  if (cb && sukat_log_glb.lvl >= lvl)
    {
      va_list ap;

      va_start(ap, fmt);
      cb(lvl, context, component, func, line, fmt, ap);
      va_end(ap);
    }
}

void sukat_log_std(sukat_log_lvl_t lvl, __attribute__((unused)) void *context,
                   const char *component, const char *func, unsigned int line,
                   const char *fmt, va_list ap)
{
  FILE *stream = (lvl == SUKAT_LOG_ERROR) ? stderr : stdout;

  fprintf(stream, "%s: %s:%u: ", component, func, line);
  vfprintf(stream, fmt, ap);
  fprintf(stream, "\n");
  fflush(stream);
}

void sukat_log_global_ctx(struct sukat_log_ctx *ctx)
{
  if (ctx)
    {
      sukat_log_glb = *ctx;
    }
  else
    {
      memset(&sukat_log_glb, 0, sizeof(sukat_log_glb));
    }
}

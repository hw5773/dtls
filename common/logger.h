#ifndef __LOGGER_H__
#define __LOGGER_H__

#include "log_types.h"

typedef struct log_st log_t;

typedef struct logger_st
{
  const char *log_prefix;
  log_t *log;
} logger_t;

logger_t *init_logger(const char *log_prefix);
void fin_logger(logger_t *logger);

#endif /* __LOGGER_H__ */

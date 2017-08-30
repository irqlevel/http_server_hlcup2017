#pragma once

#include "base.h"

void log_flush(void);

void __log(int level, const char *file, int line, const char *func, const char *fmt, ...);

enum {
    LOG_LEVEL_ERROR = 0,
    LOG_LEVEL_INFO = 1,
    LOG_LEVEL_DEBUG = 2,
};

#define log_info(fmt, ...)  \
            __log(LOG_LEVEL_INFO, __FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)

#define log_error(fmt, ...)  \
            __log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)

#ifdef __LOG_DEBUG__

#define log_debug(fmt, ...)  \
            __log(LOG_LEVEL_DEBUG, __FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)

#else

#define log_debug(fmt, ...)

#endif

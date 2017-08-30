#include "logger.h"

#ifndef __LOG_SIMPLE__

static const char *get_log_level_string(int level)
{
    switch (level)
    {
    case LOG_LEVEL_DEBUG:
        return "debug";
    case LOG_LEVEL_ERROR:
        return "error";
    case LOG_LEVEL_INFO:
        return "info";
    default:
        return "unknown";
    }
}

#endif

static FILE* get_log_level_file(int level)
{
    switch (level)
    {
    case LOG_LEVEL_DEBUG:
        return stdout;
    case LOG_LEVEL_ERROR:
        return stderr;
    case LOG_LEVEL_INFO:
        return stderr;
    default:
        bug_on(1);
        return NULL;
    }  
}

void __log(int level, const char *file, int line, const char *func, const char *fmt, ...)
{
    char buf[512];
    int n = 0;
#ifndef __LOG_SIMPLE__
	struct timeval tv;
	struct tm tm;
    time_t secs;
#endif

    va_list args;
    va_start(args, fmt);

#ifndef __LOG_SIMPLE__
	gettimeofday(&tv, NULL);
	secs = tv.tv_sec;
	gmtime_r(&secs, &tm);

    n = snprintf(buf, ARRAY_SIZE(buf), "%04d-%02d-%02d %02d:%02d:%02d.%.6ld %s %d %s,%d,%s() ",
        1900+tm.tm_year, tm.tm_mon+1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
        tv.tv_usec, get_log_level_string(level), (int)gettid(), file, line, func);
#endif

    vsnprintf(buf + n, ARRAY_SIZE(buf) - n, fmt, args);

    fprintf(get_log_level_file(level), buf);

    va_end(args);
}

void log_flush(void)
{
    fflush(stdout);
    fflush(stderr);
}
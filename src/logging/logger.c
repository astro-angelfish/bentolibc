#include "logger.h"
#include <stdio.h>
#include <stdarg.h>

enum logging_level level = INFO;

enum logging_level logger_get_level(void)
{
    return level;
}
void logger_set_level(enum logging_level new_level)
{
    level = new_level;
}

void logger_debug(const char * fmt, ...)
{
    if (level > DEBUG)
        return;
    va_list list;
    fprintf(stdout, "[DEBUG]: ");
    va_start(list, fmt);
    vfprintf(stdout, fmt, list);
    va_end(list);
    fprintf(stdout, "\n");
}
void logger_info(const char * fmt, ...)
{
    if (level > INFO)
        return;
    va_list list;
    fprintf(stdout, "[INFO]: ");
    va_start(list, fmt);
    vfprintf(stdout, fmt, list);
    va_end(list);
    fprintf(stdout, "\n");
}
void logger_warn(const char * fmt, ...)
{
    if (level > WARNING)
        return;
    va_list list;
    fprintf(stderr, "[WARN]: ");
    va_start(list, fmt);
    vfprintf(stderr, fmt, list);
    va_end(list);
    fprintf(stderr, "\n");
}
void logger_error(const char * fmt, ...)
{
    if (level > ERROR)
        return;
    va_list list;
    fprintf(stderr, "[ERROR]: ");
    va_start(list, fmt);
    vfprintf(stderr, fmt, list);
    va_end(list);
    fprintf(stderr, "\n");
}
void logger_fatal(const char * fmt, ...)
{
    if (level > FATAL)
        return;
    va_list list;
    fprintf(stderr, "[FATAL]: ");
    va_start(list, fmt);
    vfprintf(stderr, fmt, list);
    va_end(list);
    fprintf(stderr, "\n");
}

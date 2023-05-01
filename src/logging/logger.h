#ifndef BENTOLIBC_LOGGER_H
#define BENTOLIBC_LOGGER_H

enum logging_level {
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    FATAL,
    DISABLE
};

enum logging_level logger_get_level(void);
void logger_set_level(enum logging_level);

void logger_debug(const char *, ...);
void logger_info(const char *, ...);
void logger_warn(const char *, ...);
void logger_error(const char *, ...);
void logger_fatal(const char *, ...);

#endif //BENTOLIBC_LOGGER_H

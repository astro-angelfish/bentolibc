#ifndef BENTOLIBC_DISPATCHER_H
#define BENTOLIBC_DISPATCHER_H

#include "command.h"

struct command_dispatcher;
enum dispatcher_result {
    OK,
    NO_COMMAND,
    FAIL_GENERIC,
    FAIL_MEMORY
};

struct command_dispatcher * bentolibc_create_dispatcher(void);
void bentolibc_dispatch_command(struct command_dispatcher * dispatcher, int len, char ** cmdline);
void bentolibc_destroy_dispatcher(struct command_dispatcher * dispatcher);
void bentolibc_register_command(struct command_dispatcher * dispatcher, struct command_info * cmd);

#endif //BENTOLIBC_DISPATCHER_H

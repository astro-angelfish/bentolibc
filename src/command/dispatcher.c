#include "dispatcher.h"
#include "../logging/logger.h"
#include "../../hashmap.c/hashmap.h"

#include <malloc.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

struct command_dispatcher {
    struct hashmap * commands; // I hate spamming switch & cases, so I'd like to use hashmap to dispatch the command.
    bool complete;
};

void bentolibc_dispatch_command(struct command_dispatcher * dispatcher, int len, char ** cmdline)
{
    dispatcher->complete = false;
    struct command_info * cmd = hashmap_get(dispatcher->commands, &(struct command_info) { .name = *cmdline });
    if (!cmd)
    {
        logger_error("No command found.");
        dispatcher->complete = true;
        return;
    }

    cmd->func(len - 1, &cmdline[1]); // I tried to implement a C-style try catch. But who cares
}

struct command_dispatcher * bentolibc_create_dispatcher(void)
{
    struct command_dispatcher * dispatcher = malloc(sizeof(struct command_dispatcher));

    union {
        char raw_seed[2 * sizeof(int)];
        struct {
            int seed0;
            int seed1;
        };
    } seed_table;

    FILE * f = fopen("/dev/urandom", "r");
    if (!f)
    {
        logger_error("Failed to open /dev/urandom: %s", strerror(errno));
        abort();
    }
    fread(seed_table.raw_seed, sizeof(int), 2, f);
    fclose(f);

    dispatcher->commands = hashmap_new(sizeof(struct command_info), 0, seed_table.seed0, seed_table.seed1, cmd_hash, cmd_compare, NULL, NULL);
    return dispatcher;
}

void bentolibc_destroy_dispatcher(struct command_dispatcher * dispatcher)
{
    hashmap_free(dispatcher->commands); // Callers are responsible to deal with the command structure.
    free(dispatcher);
}

void bentolibc_register_command(struct command_dispatcher * dispatcher, struct command_info * cmd)
{
    hashmap_set(dispatcher->commands, cmd);
}

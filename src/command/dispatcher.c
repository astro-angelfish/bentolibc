#include "dispatcher.h"
#include "../logging/logger.h"
#include "../../hashmap.c/hashmap.h"

#include <malloc.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <ucontext.h>
#include <sys/ucontext.h>

const int signal_to_handle[] = { SIGABRT, SIGSEGV, SIGILL, 0 };

struct command_dispatcher {
    struct hashmap * commands; // I hate spamming switch & cases, so I'd like to use hashmap to dispatch the command.
    enum dispatcher_result result;
    bool complete;
    ucontext_t * saved_context;
};

void handle_signal(int signal, siginfo_t * info, void * data)
{
    ucontext_t * ctx = data;
    struct command_dispatcher * dispatcher = (struct command_dispatcher *) ctx->uc_mcontext.gregs[REG_R11];
    dispatcher->complete = true;
    if (signal == SIGSEGV || signal == SIGILL)
        dispatcher->result = FAIL_MEMORY;
    else
        dispatcher->result = FAIL_GENERIC;

    logger_error("Error while executing command.");

    // Dirty register hack to restore states.
    greg_t rip = ctx->uc_mcontext.gregs[REG_R12];
    memcpy(ctx, dispatcher->saved_context, sizeof(ucontext_t));
    ctx->uc_mcontext.gregs[REG_RIP] = rip;
    ctx->uc_mcontext.gregs[REG_R11] = (long long)dispatcher;
}

#pragma clang diagnostic push
#pragma ide diagnostic ignored "UnusedValue"
#pragma ide diagnostic ignored "UnusedLocalVariable"
#pragma ide diagnostic ignored "UnreachableCode"
void bentolibc_dispatch_command(struct command_dispatcher * dispatcher, int len, char ** cmdline)
{
    dispatcher->complete = false;
    struct command_info * cmd = hashmap_get(dispatcher->commands, &(struct command_info) { .name = *cmdline });
    if (!cmd)
    {
        logger_error("No command found.");
        dispatcher->complete = true;
        dispatcher->result = NO_COMMAND;
        return;
    }

    // Setup signal
    struct sigaction action = { .sa_sigaction = handle_signal };
    struct sigaction old_action[SIGRTMAX];

    for (int i = 0; signal_to_handle[i]; i ++)
        sigaction(signal_to_handle[i], &action, &old_action[i]);
    dispatcher->saved_context = malloc(sizeof(ucontext_t));

    // Save the current context.
    // We'll be okay as long as the command function does not use r11 & r12
    getcontext(dispatcher->saved_context);
    __attribute__((unused)) register struct command_dispatcher * context asm("r11") = dispatcher;
    __attribute__((unused)) register void * ptr asm("r12") = &&cleanup;

    cmd->func(len - 1, &cmdline[1]);

    cleanup:
    for (int i = 0; signal_to_handle[i]; i ++)
        sigaction(signal_to_handle[i], &old_action[i], NULL);

    if (!dispatcher->complete)
    {
        dispatcher->result = OK;
        dispatcher->complete = true;
    }
}
#pragma clang diagnostic pop

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

enum dispatcher_result bentolibc_dispatcher_errno(struct command_dispatcher * dispatcher)
{
    return dispatcher->result;
}

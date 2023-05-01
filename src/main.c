#include "config/config.h"
#include "logging/logger.h"
#include "command/dispatcher.h"

int main(int argc, char ** argv)
{
    struct bentolibc_config * config = bentolibc_load_config();
    struct command_dispatcher * dispatcher = bentolibc_create_dispatcher();
    int exit_code = 0;

    if (argc < 1)
    {
        logger_fatal("No command provided.");
        char * helpCmd[] = { "help" };
        bentolibc_dispatch_command(dispatcher, 1, helpCmd);
        exit_code = 1;
        goto cleanup;
    }

    bentolibc_dispatch_command(dispatcher, argc, argv);

    cleanup:
    bentolibc_destroy_dispatcher(dispatcher);
    bentolibc_destroy_config(config);
    return exit_code;
}

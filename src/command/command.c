#include "command.h"
#include <string.h>
#include "../../hashmap.c/hashmap.h"

int cmd_compare(const void * a, const void * b, void * udata)
{
    const struct command_info * ca = a;
    const struct command_info * cb = b;
    return strcmp(ca->name, cb->name);
}

unsigned long int cmd_hash(const void * item, unsigned long int seed0, unsigned long int seed1)
{
    const struct command_info * cmd = item;
    return hashmap_sip(cmd->name, strlen(cmd->name), seed0, seed1);
}

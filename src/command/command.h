#ifndef BENTOLIBC_COMMAND_H
#define BENTOLIBC_COMMAND_H

typedef void(*command_func_t)(int, char**);
struct command_info {
    char * name;
    command_func_t func;
};

int cmd_compare(const void * a, const void * b, void * udata);
unsigned long int cmd_hash(const void * item, unsigned long int seed0, unsigned long int seed1);

#endif //BENTOLIBC_COMMAND_H

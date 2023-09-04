#ifndef BENTOLIBC_ONEGADGET_H
#define BENTOLIBC_ONEGADGET_H

#include <stdlib.h>

enum constraint_type_t {
    CONSTRAINT_REG,
    CONSTRAINT_MEM
};

struct constraint_t {
    enum constraint_type_t type;

    union {
        char* reg;
        struct {
            char* base;
            size_t offset;
        } mem;
    };
    size_t value;
};

struct one_gadget_t {
    unsigned long int address;
    size_t num_constraints;
    struct constraint_t* constraints;

    size_t emulated_binsh_pos;
};

struct one_gadget_t* bentolibc_fetch_x86_one_gadget(void* data, size_t length, size_t base, size_t* num_gadgets);
struct one_gadget_t* bentolibc_fetch_x64_one_gadget(void* data, size_t length, size_t base, size_t* num_gadgets);

#endif //BENTOLIBC_ONEGADGET_H

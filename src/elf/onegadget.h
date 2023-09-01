#ifndef BENTOLIBC_ONEGADGET_H
#define BENTOLIBC_ONEGADGET_H

#include <stdlib.h>

struct constraint_t {
    size_t type;
    union {
        struct {
            char* reg;
            size_t imm;
        } reg_imm;
        struct {
            char* reg1;
            char* reg2;
        } reg_reg;
        struct {
            char* reg1;
            char* reg_base;
            size_t offset;
        } reg_mem;
        struct {
            char* reg_base;
            size_t offset;
            size_t imm;
        } mem_imm;
        struct {
            char* reg_base;
            size_t offset;
            char* reg_index;
            size_t scale;
        } mem_reg;
    } data;
};

struct one_gadget_t {
    unsigned long int address;
    size_t num_constraints;
    struct constraint_t* constraints;
};

struct one_gadget_t* bentolibc_fetch_x86_one_gadget(void* data, size_t length, size_t base, size_t* num_gadgets);
struct one_gadget_t* bentolibc_fetch_x64_one_gadget(void* data, size_t length, size_t base, size_t* num_gadgets);

#endif //BENTOLIBC_ONEGADGET_H

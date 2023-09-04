#include <string.h>
#include <stdbool.h>
#include "onegadget.h"
#include "../logging/logger.h"
#include <unicorn/unicorn.h>
#include "../fadec/fadec.h"
#include <time.h>
#include <errno.h>

struct memory_context_t {
    size_t address;
    char* alphabet;
};

struct memory_context_holder_t {
    size_t size;
    struct memory_context_t* contexts;
};

struct x86_reg_data {
    union {
        char value[4];
        int int_val;
    };
    char* last_from_reg;
    int last_modified;
};
union x64_reg_data {
    char value[8];
    long int int_val;
};

size_t find_de_bruijn_idx(char* subseq, char* alphabet);

static bool hook_memalloc_x86(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);

struct constraint_t x86_make_constraint(struct x86_reg_data reg_data, struct x86_reg_data sp, struct x86_reg_data bp, char* reg_name, struct memory_context_holder_t context, int expect_val)
{
    struct constraint_t constraint;
    // Find the cyclic to check if ecx is from memory
    for (int i = 0; i < context.size; i ++)
    {
        struct memory_context_t ctx = context.contexts[i];
        int idx = find_de_bruijn_idx(reg_data.value, ctx.alphabet);
        if (idx != -1)
        {
            // Go for other registers
            if (sp.int_val > ctx.address && sp.int_val < ctx.address + 2 * 1024 * 1024)
            {
                constraint.type = CONSTRAINT_MEM;
                constraint.mem.base = "esp";
                constraint.mem.offset = sp.int_val - ctx.address - idx;
                constraint.value = expect_val;
            }
            else if (sp.int_val > ctx.address && sp.int_val < ctx.address + 2 * 1024 * 1024)
            {
                constraint.type = CONSTRAINT_MEM;
                constraint.mem.base = "ebp";
                constraint.mem.offset = sp.int_val - ctx.address - idx;
                constraint.value = expect_val;
            }
//            else if (reg_data.last_from_reg)
//            {
//                // TODO: We'll handle registers transfer to each other when unicorn supports.
//            }
            else
            {
                constraint.type = CONSTRAINT_REG;
                constraint.reg = reg_name;
                constraint.value = expect_val - reg_data.int_val;
            }
        }
    }
}

struct one_gadget_t* bentolibc_fetch_x86_one_gadget(void* data, size_t length, size_t base, size_t* num_gadgets)
{
    // int 0x80 based syscall first
    // Look for eax constraints

    // SYS_execve constraints: eax == 0xb, ebx == "/bin/sh", ecx == 0, edx == 0
    const char* eax_execve = "\xb8\x0b\x00\x00\x00";

    // SYS_execveat constraints: eax == 0x69, ebx == -100, ecx == "/bin/sh", edx == 0, esi == 0
    const char* eax_execveat = "\xb8""f\x01\x00\x00";

    void** possibilities = NULL;
    unsigned int possibility_count = 0;

    struct one_gadget_t* result = NULL;

    for (unsigned int j = 0; j < length; j ++)
    {
        void* instruction_check = data + j;
        if (!memcmp(instruction_check, eax_execve, 5))
        {
            void** old_possibilities = possibilities;
            possibilities = realloc(possibilities, sizeof(void*) * (possibility_count + 1));
            if (!possibilities)
            {
                logger_error("Unable to dump one-gadgets: Unable to allocate memory: %s", strerror(errno));
                possibilities = old_possibilities;
                goto cleanup;
            }

            possibilities[possibility_count ++] = instruction_check;
        }
        else if (!memcmp(instruction_check, eax_execveat, 5))
        {
            void** old_possibilities = possibilities;
            possibilities = realloc(possibilities, sizeof(void*) * (possibility_count + 1));
            if (!possibilities)
            {
                logger_error("Unable to dump one-gadgets: Unable to allocate memory: %s", strerror(errno));
                possibilities = old_possibilities;
                goto cleanup;
            }

            possibilities[possibility_count ++] = instruction_check;
        }
    }

    // Look for int 0x80 syscall by parsing instructions.
    for (unsigned int j = 0; j < possibility_count; j ++)
    {
        void* instruction_check = possibilities[j] + 5;

        uc_engine *uc;
        uc_err err;
        bool uc_fail = false;

        err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
        if (err != UC_ERR_OK)
        {
            logger_error("Unable to dump one-gadgets: Unicorn initialization failed: %s", uc_strerror(err));
            return NULL;
        }

        err = uc_mem_map(uc, 0x1000, 2 * 1024 * 1024, UC_PROT_ALL);
        if (err != UC_ERR_OK)
        {
            logger_error("Unable to dump one-gadgets: Unicorn memory mapping failed: %s", uc_strerror(err));
            return NULL;
        }
        int desired_stack_pos = 0x08000000;
        uc_reg_write(uc, UC_X86_REG_ESP, &desired_stack_pos);
        uc_reg_write(uc, UC_X86_REG_EBP, &desired_stack_pos);

        // Scan for syscalls to get desired size
        while (1)
        {
            size_t inst_size = 1;
            FdInstr instr;
            while (fd_decode(instruction_check, inst_size, 32, 0, &instr) < 0)
                if (inst_size++ > 15)
                {
                    logger_error("Unable to dump one-gadgets: Failed to decode instruction at %p", instruction_check);
                    goto uc_cleanup;
                }
            if (!memcmp(instruction_check, "\xcd\x80", 2)) // We will stop by and check again in the unicorn
                break;
            instruction_check += inst_size;
        }

        // Copy instructions into Unicorn memory
        err = uc_mem_write(uc, 0x1000, possibilities[j], instruction_check - possibilities[j]);
        if (err != UC_ERR_OK)
        {
            logger_error("Unable to dump one-gadgets: Unicorn memory write failed: %s", uc_strerror(err));
            goto uc_cleanup;
        }

        uc_hook trace, mov_trace;
        struct memory_context_holder_t context = { 0 };
        err = uc_hook_add(uc, &trace, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_memalloc_x86, &context, 1, 0);
        if (err != UC_ERR_OK)
        {
            logger_error("Unable to dump one-gadgets: Page fault hook failed: %s", uc_strerror(err));
            goto uc_cleanup;
        }

        // Simulate the execution
        err = uc_emu_start(uc, 0x1000, 0x1000 + (instruction_check - possibilities[j]), 0, 0);
        if (err != UC_ERR_OK)
        {
            logger_error("Unable to dump one-gadgets: Unicorn emulation failed: %s", uc_strerror(err));
            goto uc_cleanup;
        }

        // Ok, got the registers we want to control
        struct x86_reg_data eax, ebx, ecx, edx, esi, esp, ebp;
        uc_reg_read(uc, UC_X86_REG_EAX, &eax);
        uc_reg_read(uc, UC_X86_REG_EBX, &ebx);
        uc_reg_read(uc, UC_X86_REG_ECX, &ecx);
        uc_reg_read(uc, UC_X86_REG_EDX, &edx);
        uc_reg_read(uc, UC_X86_REG_ESI, &esi);
        uc_reg_read(uc, UC_X86_REG_ESP, &esp);
        uc_reg_read(uc, UC_X86_REG_EBP, &ebp);

        struct one_gadget_t one_gadget = { 0 };
        switch (eax.int_val)
        {
            case 0xb:
                one_gadget.emulated_binsh_pos = ebx.int_val;
                if (ecx.int_val)
                {
                    struct constraint_t ecx_constraint = x86_make_constraint(ecx, esp, ebp, "ecx", context, 0);

                    struct constraint_t* old_constraints = one_gadget.constraints;
                    one_gadget.constraints = realloc(one_gadget.constraints, sizeof(struct constraint_t) * (one_gadget.num_constraints + 1));
                    if (!one_gadget.constraints)
                    {
                        logger_error("Unable to dump one-gadgets: Unable to allocate memory: %s", strerror(errno));
                        free(old_constraints);
                        uc_fail = true;
                        goto uc_cleanup;
                    }
                    one_gadget.constraints[one_gadget.num_constraints ++] = ecx_constraint;
                }
                if (edx.int_val)
                {
                    struct constraint_t edx_constraint = x86_make_constraint(edx, esp, ebp, "edx", context, 0);

                    struct constraint_t* old_constraints = one_gadget.constraints;
                    one_gadget.constraints = realloc(one_gadget.constraints, sizeof(struct constraint_t) * (one_gadget.num_constraints + 1));
                    if (!one_gadget.constraints)
                    {
                        logger_error("Unable to dump one-gadgets: Unable to allocate memory: %s", strerror(errno));
                        free(old_constraints);
                        uc_fail = true;
                        goto uc_cleanup;
                    }
                    one_gadget.constraints[one_gadget.num_constraints ++] = edx_constraint;
                }
                break;
            case 0x69:
                one_gadget.emulated_binsh_pos = ecx.int_val;
                if (ebx.int_val)
                {
                    struct constraint_t ebx_constraint = x86_make_constraint(ebx, esp, ebp, "ebx", context, -100);

                    struct constraint_t* old_constraints = one_gadget.constraints;
                    one_gadget.constraints = realloc(one_gadget.constraints, sizeof(struct constraint_t) * (one_gadget.num_constraints + 1));
                    if (!one_gadget.constraints)
                    {
                        logger_error("Unable to dump one-gadgets: Unable to allocate memory: %s", strerror(errno));
                        free(old_constraints);
                        uc_fail = true;
                        goto uc_cleanup;
                    }
                    one_gadget.constraints[one_gadget.num_constraints ++] = ebx_constraint;
                }
                if (edx.int_val)
                {
                    struct constraint_t edx_constraint = x86_make_constraint(edx, esp, ebp, "edx", context, 0);

                    struct constraint_t* old_constraints = one_gadget.constraints;
                    one_gadget.constraints = realloc(one_gadget.constraints, sizeof(struct constraint_t) * (one_gadget.num_constraints + 1));
                    if (!one_gadget.constraints)
                    {
                        logger_error("Unable to dump one-gadgets: Unable to allocate memory: %s", strerror(errno));
                        free(old_constraints);
                        uc_fail = true;
                        goto uc_cleanup;
                    }
                    one_gadget.constraints[one_gadget.num_constraints ++] = edx_constraint;
                }
                if (esi.int_val)
                {
                    struct constraint_t esi_constraint = x86_make_constraint(esi, esp, ebp, "esi", context, 0);

                    struct constraint_t* old_constraints = one_gadget.constraints;
                    one_gadget.constraints = realloc(one_gadget.constraints, sizeof(struct constraint_t) * (one_gadget.num_constraints + 1));
                    if (!one_gadget.constraints)
                    {
                        logger_error("Unable to dump one-gadgets: Unable to allocate memory: %s", strerror(errno));
                        free(old_constraints);
                        uc_fail = true;
                        goto uc_cleanup;
                    }
                    one_gadget.constraints[one_gadget.num_constraints ++] = esi_constraint;
                }
                break;
            default:
                uc_fail = true;
                break;
        }

        uc_cleanup:
        uc_close(uc);
        if (context.size)
        {
            for (unsigned int i = 0; i < context.size; i ++)
                free(context.contexts[i].alphabet);
            free(context.contexts);
        }

        if (uc_fail)
            goto cleanup;
        else
        {
            result = realloc(result, sizeof(struct one_gadget_t) * (*num_gadgets + 1));
            if (!result)
            {
                logger_error("Unable to dump one-gadgets: Unable to allocate memory: %s", strerror(errno));
                goto cleanup;
            }
            result[*num_gadgets] = one_gadget;
            (*num_gadgets) ++;
        }
    }

    cleanup:
    if (possibilities)
        free(possibilities);
    return result;
}

struct one_gadget_t* bentolibc_fetch_x64_one_gadget(void* data, size_t length, size_t base, size_t* num_gadgets)
{

}

// de bruijn sequence generator taken from https://en.wikipedia.org/wiki/De_Bruijn_sequence
void db(int t, int p, int n, int* sequence, int* a, int k)
{
    int i;
    if (t > n)
    {
        if (n % p == 0)
        {
            for (i = 1; i <= p; i++)
            {
                sequence[i - 1] = a[i];
            }
        }
    }
    else
    {
        a[t] = a[t - p];
        db(t + 1, p, n, sequence, a, k);
        for (int j = a[t - p] + 1; j < k; j++)
        {
            a[t] = j;
            db(t + 1, t, n, sequence, a, k);
        }
    }
}
const char* de_bruijn_alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

char* de_bruijn(char** alphabet, int n)
{
    if (!alphabet)
        return NULL;
    if (!*alphabet) // We need to shuffle the alphabet to make each memory unique, at least there is unlikely a collision.
    {
        *alphabet = strdup(de_bruijn_alphabet);
        srand(time(NULL));
        for (int i = 0; i < strlen(*alphabet); i++)
        {
            int j = rand() % strlen((*alphabet));
            char tmp = (*alphabet)[i];
            (*alphabet)[i] = (*alphabet)[j];
            (*alphabet)[j] = tmp;
        }
    }

    int i;
    int *a = (int *) malloc(n * sizeof(int));
    int *sequence = (int *) malloc(n * sizeof(int));
    for (i = 0; i < n; i++)
    {
        a[i] = 0;
        sequence[i] = 0;
    }

    db(1, 1, n, sequence, a, strlen((*alphabet)));
    char *result = (char *) malloc((n + 1) * sizeof(char));
    for (i = 0; i < n; i++)
    {
        result[i] = (*alphabet)[sequence[i]];
    }
    result[n] = '\0';
    return result;
}
size_t find_de_bruijn_idx(char* subseq, char* alphabet)
{
    char* sequence = de_bruijn(&alphabet, strlen(subseq));
    char* idx = strstr(sequence, subseq);
    if (!idx)
        return -1;
    return idx - sequence;
}

static bool hook_memalloc_x86(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
    size_t aligned = address & ~0xfff;
    uc_err err = uc_mem_map(uc, aligned, 2 * 1024 * 1024, UC_PROT_ALL);
    if (err != UC_ERR_OK)
    {
        logger_error("Unable to dump one-gadgets: Unicorn memory mapping failed: %s", uc_strerror(err));
        return false;
    }

    struct memory_context_holder_t* memory_context_holder = (struct memory_context_holder_t*) user_data;
    void* old_ctx = memory_context_holder->contexts;
    memory_context_holder->contexts = realloc(memory_context_holder->contexts, sizeof(struct memory_context_t) * (memory_context_holder->size + 1));
    if (!memory_context_holder->contexts)
    {
        logger_error("Unable to dump one-gadgets: Unable to allocate memory: %s", strerror(errno));
        memory_context_holder->contexts = old_ctx;
        return false;
    }

    // Cyclic the data of memory
    char* sequence = de_bruijn(&memory_context_holder->contexts[memory_context_holder->size].alphabet, 2 * 1024 * 1024);
    memory_context_holder->size ++;

    err = uc_mem_write(uc, aligned, sequence, 2 * 1024 * 1024);
    if (err != UC_ERR_OK)
    {
        logger_error("Unable to dump one-gadgets: Unicorn memory write failed: %s", uc_strerror(err));
        return false;
    }

    return true;
}

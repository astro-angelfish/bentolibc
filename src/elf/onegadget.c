#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include "onegadget.h"

#include "../../fadec/fadec.h"

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

    for (unsigned int j = 0; j < length; j ++)
    {
        void* instruction_check = data + j;
        if (!memcmp(instruction_check, eax_execve, 5))
        {
            possibilities = realloc(possibilities, sizeof(void*) * (possibility_count + 1));
            if (!possibilities)
                raise(SIGSEGV);

            possibilities[possibility_count ++] = instruction_check;
        }
        else if (!memcmp(instruction_check, eax_execveat, 5))
        {
            possibilities = realloc(possibilities, sizeof(void*) * (possibility_count + 1));
            if (!possibilities)
                raise(SIGSEGV);

            possibilities[possibility_count ++] = instruction_check;
        }
    }

    // Look for int 0x80 syscall by parsing instructions.
    for (unsigned int j = 0; j < possibility_count; j ++)
    {
        void* instruction_check = possibilities[j] + 5;
        size_t found_constraints = 0;

        bool fail = false;
        for (unsigned int k = 0; true; k ++) // There are multiple conditions that can lead to a search ending.
        {
            // int 0x80, sysenter, syscall
            if (!memcmp(instruction_check, "\xcd\x80", 2) || !memcmp(instruction_check, "\x0f\x34", 2) || !memcmp(instruction_check, "\x0f\x05", 2))
            {
                break;
            }

            FdInstr parsed_instruction;
            size_t inst_len = 1;
            while (fd_decode(instruction_check, inst_len, 32, base, &parsed_instruction) < 0)
            {
                if (inst_len++ > 15)
                    break;
            }
            if (inst_len > 15) // Corrupted area
            {
                fail = true;
                break;
            }

            switch (FD_TYPE(&parsed_instruction))
            {
                case FDI_JCXZ:
                case FDI_JC:
                case FDI_JBE:
                case FDI_JA:
                case FDI_JG:
                case FDI_JGE:
                case FDI_JL:
                case FDI_JLE:
                case FDI_JMP:
                case FDI_JNO:
                case FDI_JNP:
                case FDI_JNS:
                case FDI_JO:
                case FDI_JP:
                case FDI_JS:
                case FDI_LOOP:
                case FDI_LOOPZ:
                case FDI_LOOPNZ:
                case FDI_JMPF:
                case FDI_JNC:
                case FDI_JNZ:
                case FDI_JZ:
                    // TODO: These jump are confusing and probably breaks our plan, and does not seem to appear often in glibc. For now we just treat them as bad.
                    fail = true;
                    break;
            }

            if (fail)
                break;
        }
    }
}
struct one_gadget_t* bentolibc_fetch_x64_one_gadget(void* data, size_t length, size_t base, size_t* num_gadgets)
{

}

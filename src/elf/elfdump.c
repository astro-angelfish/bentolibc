#include "elfdump.h"
#include "../../hashmap.c/hashmap.h"
#include "../logging/logger.h"
#include <malloc.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <elf.h>
#include <assert.h>
#include <ucontext.h>
#include <signal.h>

// Reference: https://wiki.osdev.org/ELF_Tutorial

struct elf_data {
    char * name;
    struct hashmap * symbol_map;
    struct hashmap * reverse_symbol_map;

    unsigned string_count;
    char ** string_table;
};

struct symbol_data {
    char * name;
    unsigned long int address;
};

struct one_gadget_data {
    unsigned long int address;
    fpregset_t constraints;
};

int symbol_compare_name(const void * a, const void * b, void * udata)
{
    const struct symbol_data * fa = a;
    const struct symbol_data * fb = b;
    return strcmp(fa->name, fb->name);
}

int symbol_compare_address(const void * a, const void * b, void * udata)
{
    const struct symbol_data * fa = a;
    const struct symbol_data * fb = b;
    return fa->address > fb->address ? 1 : (fa->address < fb->address ? -1 : 0);
}

unsigned long int symbol_hash_name(const void * item, unsigned long int seed0, unsigned long int seed1)
{
    const struct symbol_data * func = item;
    return hashmap_sip(func->name, strlen(func->name), seed0, seed1);
}

unsigned long int symbol_hash_address(const void * item, unsigned long int seed0, unsigned long int seed1)
{
    const struct symbol_data * func = item;
    return hashmap_sip(&func->address, sizeof(unsigned long int), seed0, seed1);
}

static void dump_x86_elf(struct elf_data * target, void * data, Elf32_Ehdr header, unsigned long size)
{
    assert(header.e_phentsize == sizeof(Elf32_Phdr));
    assert(header.e_shentsize == sizeof(Elf32_Shdr));

    void * ptr = data + header.e_shoff;
    Elf32_Shdr* section_headers = (Elf32_Shdr *) ptr;

    for (unsigned int i = 0; i < header.e_shnum; i ++)
    {
        Elf32_Shdr section_header = section_headers[i];

        if (section_header.sh_type == SHT_SYMTAB)
        {
            assert(section_header.sh_size % sizeof(Elf32_Sym) == 0);

            Elf32_Sym * symbol_table = malloc(section_header.sh_size);
            unsigned int symbol_count = section_header.sh_size / sizeof(Elf32_Sym);
            memcpy(symbol_table, data + section_header.sh_offset, sizeof(section_header.sh_size));

            // Reveal all symbols.
            for (unsigned int j = 0; j < symbol_count; j ++)
            {
                Elf32_Sym symbol = symbol_table[j];
                if (!symbol.st_name)
                    continue;
                if (symbol.st_shndx == SHN_UNDEF) // External symbol. We can safely ignore that
                    continue;
                else if (symbol.st_shndx == SHN_ABS)
                {
                    struct symbol_data *symbol_data = malloc(sizeof(struct symbol_data));
                    symbol_data->name = malloc(sizeof(char) * (strlen(target->string_table[symbol.st_name]) + 1));
                    memset(symbol_data->name, 0, sizeof(char) * (strlen(target->string_table[symbol.st_name]) + 1));
                    strcpy(symbol_data->name, target->string_table[symbol.st_name]);

                    symbol_data->address = symbol.st_value;
                    hashmap_set(target->symbol_map, symbol_data);
                    hashmap_set(target->reverse_symbol_map, symbol_data);
                }
                else // Relative symbols.
                {
                    struct symbol_data *symbol_data = malloc(sizeof(struct symbol_data));
                    symbol_data->name = malloc(sizeof(char) * (strlen(target->string_table[symbol.st_name]) + 1));
                    memset(symbol_data->name, 0, sizeof(char) * (strlen(target->string_table[symbol.st_name]) + 1));
                    strcpy(symbol_data->name, target->string_table[symbol.st_name]);

                    symbol_data->address = symbol.st_value + section_headers[symbol.st_shndx].sh_addr;
                    hashmap_set(target->symbol_map, symbol_data);
                    hashmap_set(target->reverse_symbol_map, symbol_data);
                }
            }
        }
        else if (section_header.sh_type == SHT_STRTAB)
        {
            assert(!*(char *)(data + section_header.sh_size + section_header.sh_offset));

            unsigned int string_count = 0;
            // Count 0s to determine the string table.
            for (unsigned int j = 0; j < section_header.sh_size; j ++)
                if (!(char *)(data + j + section_header.sh_offset))
                    string_count ++;
            string_count --; // There is a 0 at the beginning.

            target->string_count = string_count;
            target->string_table = malloc(sizeof(char *) * string_count);

            void * str_ptr = data + section_header.sh_offset + 1;
            unsigned int check_count = 0;
            while ((unsigned long) (str_ptr - section_header.sh_offset) < section_header.sh_size)
            {
                target->string_table[check_count] = malloc(sizeof(char) * (strlen(str_ptr) + 1)); // Avoid off-by-zero
                memset(target->string_table[string_count], 0, sizeof(char) * (strlen(str_ptr) + 1));
                strcpy(target->string_table[check_count ++], str_ptr);
                str_ptr += strlen(str_ptr) + 1;
            }

            assert(check_count == target->string_count);
        }
        else if (section_header.sh_type == SHT_PROGBITS)
        {
            if (section_header.sh_flags & SHF_EXECINSTR) // Alright, go for one-gadgets
            {
                // int 0x80 based syscall first
                // Look for eax constraints
                const char* eax_execve = "\xb8\x0b\x00\x00\x00";
                const char* eax_execveat = "\xb8""f\x01\x00\x00";

                void** possibilities = NULL;
                unsigned int possibility_count = 0;

                for (unsigned int j = 0; j < section_header.sh_size; j ++)
                {
                    void* instruction_check = data + section_header.sh_offset + j;
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
                    void* instruction_check = possibilities[j];
                    for (unsigned int k = 0; true; k ++) // There are multiple conditions that can lead to a search ending.
                    {
                        void* finder = target + 5;

                    }
                }
            }
        }
    }
}

static void dump_x86_64_elf(struct elf_data * target, void * data, Elf64_Ehdr header, unsigned long size)
{

}

struct elf_data * bentolibc_dump_elf(char * name, char * elf_file)
{
    struct elf_data * result = bentolibc_create_elf(name);

    FILE * target = fopen(elf_file, "rb");
    if (!target)
    {
        logger_error("Unable to read %s: %s", name, strerror(errno));
        abort();
    }
    int fd = fileno(target);
    long size = ftell(target);

    void * mapped_elf = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (!mapped_elf)
    {
        logger_error("Unable to allocate a mapping for %s: %s", name, strerror(errno));
        abort();
    }

    if (memcmp(mapped_elf, ELFMAG, 4 * sizeof(char)))
    {
        logger_error("Not a valid ELF file.");
        abort();
    }

    Elf64_Ehdr header;
    memcpy(&header, mapped_elf, sizeof(Elf64_Ehdr));
    if (header.e_ident[EI_CLASS] == ELFCLASS32)
    {
        Elf32_Ehdr header_x32;
        memcpy(&header_x32, mapped_elf, sizeof(Elf32_Ehdr));
        dump_x86_elf(result, mapped_elf, header_x32, size);
    }
    else if (header.e_ident[EI_CLASS] == ELFCLASS64)
        dump_x86_64_elf(result, mapped_elf, header, size);
    else
    {
        logger_error("Unsupported elf type: %d", header.e_type);
        abort();
    }

    munmap(mapped_elf, size);
    fclose(target);

    return result;
}

struct elf_data * bentolibc_create_elf(char * name)
{
    struct elf_data * result = malloc(sizeof(struct elf_data));

    result->name = malloc(sizeof(char) * strlen(name));
    strcpy(result->name, name);

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

    result->symbol_map = hashmap_new(sizeof(struct symbol_data), 0, seed_table.seed0, seed_table.seed1, symbol_hash_name,
                                     symbol_compare_name, NULL, NULL);

    fread(seed_table.raw_seed, sizeof(int), 2, f);
    result->reverse_symbol_map = hashmap_new(sizeof(struct symbol_data), 0, seed_table.seed0, seed_table.seed1,
                                             symbol_hash_address, symbol_compare_address, NULL, NULL);

    fclose(f);

    return result;
}

unsigned long int bentolibc_get_symbol_info(struct elf_data * data, char * name);
void bentolibc_put_symbol_info(struct elf_data * data, char * name, unsigned long int address);

void bentolibc_destroy_elf(struct elf_data * data)
{
    hashmap_free(data->reverse_symbol_map);
    hashmap_free(data->symbol_map);
    free(data->name);
    free(data);
}

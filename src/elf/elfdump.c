#include "elfdump.h"
#include "../../hashmap.c/hashmap.h"
#include <malloc.h>
#include <string.h>

struct elf_data {
    char * name;
    struct hashmap * func_map;
};

struct func_data {
    char * name;
    unsigned long int address;
};

struct elf_data * bentolibc_dump_elf(char * name, char * elf_file)
{

}
struct elf_data * bentolibc_create_elf(char * name)
{
    struct elf_data * result = malloc(sizeof(struct elf_data));

    result->name = malloc(sizeof(char) * strlen(name));
    strcpy(result->name, name);



    return result;
}

unsigned long int bentolibc_get_func_info(struct elf_data * data, char * name);
void bentolibc_put_func_info(struct elf_data * data, char * name, unsigned long int address);

void bentolibc_destroy_elf(struct elf_data *);

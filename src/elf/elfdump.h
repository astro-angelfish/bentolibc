#ifndef BENTOLIBC_ELFDUMP_H
#define BENTOLIBC_ELFDUMP_H

struct elf_data;

struct elf_data * bentolibc_dump_elf(char * name, char * elf_file);
struct elf_data * bentolibc_create_elf(char * name);

unsigned long int bentolibc_get_func_info(struct elf_data * data, char * name);
void bentolibc_put_func_info(struct elf_data * data, char * name, unsigned long int address);

void bentolibc_destroy_elf(struct elf_data *);

#endif //BENTOLIBC_ELFDUMP_H

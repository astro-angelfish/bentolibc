#ifndef BENTOLIBC_CONFIG_H
#define BENTOLIBC_CONFIG_H

struct bentolibc_postgresql_config {
    char * url;
    char * username;
    char * password;
    char * database;
};

struct bentolibc_config {
    struct bentolibc_postgresql_config postgresql_config;
    char * storage_dir;
};

struct bentolibc_config * bentolibc_load_config(void);
void bentolibc_destroy_config(struct bentolibc_config *);

#endif //BENTOLIBC_CONFIG_H

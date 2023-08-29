#ifndef BENTOLIBC_CONFIG_H
#define BENTOLIBC_CONFIG_H

struct bentolibc_postgresql_config {
    char * url;
    char * username;
    char * password;
    char * database;
};

struct bentolibc_server_config {
    int enabled;
    char * host;
    int port;
    struct bentolibc_postgresql_config postgresql_config;
};

struct bentolibc_client_config {
    int local;
    int share;
    char * storage_dir;

    int num_servers;
    char ** servers;
};

struct bentolibc_config {
    int version;
    struct bentolibc_server_config server_config;
    struct bentolibc_client_config client_config;
};

struct bentolibc_config * bentolibc_load_config(void);
void bentolibc_destroy_config(struct bentolibc_config *);

#endif //BENTOLIBC_CONFIG_H

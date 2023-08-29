#include "config.h"
#include "../logging/logger.h"

#include <libconfig.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>

#define CONFIG_PATH "/home/astro-angelfish/program-dev/bentolibc/src/bentolibc.cfg"
//#define CONFIG_PATH "/etc/bentolibc/bentolibc.cfg"

// config_lookup_string would leave us a use-after-free. We'd better to lookup them by ourselves.
void config_get_string(config_t* cfg, const char* path, char ** value)
{
    config_setting_t* setting = config_lookup(cfg, path);
    const char* val = config_setting_get_string(setting);
    *value = malloc(sizeof(char) * (strlen(val) + 1));
    memset(*value, 0, sizeof(char) * (strlen(val) + 1));
    memcpy(*value, val, sizeof(char) * strlen(val));
}

struct bentolibc_config * bentolibc_load_config(void)
{
    logger_info("Loading config");
    config_t * cfg = malloc(sizeof(config_t));
    struct bentolibc_config * config = malloc(sizeof(struct bentolibc_config));
    memset(config, 0, sizeof(struct bentolibc_config));
    memset(cfg, 0, sizeof(config_t));

    if (config_read_file(cfg, CONFIG_PATH) == CONFIG_FALSE)
    {
        logger_error("Failed to read configuration: %s, at %d in %s", cfg->error_text, cfg->error_line, cfg->error_file);
        abort();
    }

    config_lookup_bool(cfg, "server.enabled", &config->server_config.enabled);
    config_get_string(cfg, "server.host", &config->server_config.host);
    config_lookup_int(cfg, "server.port", &config->server_config.port);

    config_get_string(cfg, "server.postgresql.url", &config->server_config.postgresql_config.url);
    config_get_string(cfg, "server.postgresql.user", &config->server_config.postgresql_config.username);
    config_get_string(cfg, "server.postgresql.pass", &config->server_config.postgresql_config.password);
    config_get_string(cfg, "server.postgresql.database", &config->server_config.postgresql_config.database);

    config_lookup_bool(cfg, "client.local", &config->client_config.local);
    config_lookup_bool(cfg, "client.share", &config->client_config.share);
    config_get_string(cfg, "client.storage", &config->client_config.storage_dir);
    config_setting_t* servers = config_lookup(cfg, "client.servers");
    config->client_config.num_servers = config_setting_length(servers);
    config->client_config.servers = malloc(sizeof(char *) * config->client_config.num_servers);
    for (size_t i = 0; i < config->client_config.num_servers; i++)
    {
        config_setting_t* server = config_setting_get_elem(servers, i);
        config->client_config.servers[i] = malloc(sizeof(char) * (strlen(config_setting_get_string(server)) + 1));
        strcpy(config->client_config.servers[i], config_setting_get_string(server));
    }

    config_destroy(cfg);

    free(cfg);
    logger_info("Config loading completed");
    return config;
}

void bentolibc_destroy_config(struct bentolibc_config * cfg)
{
    for (int idx = 0; idx < cfg->client_config.num_servers; idx ++)
        free(cfg->client_config.servers[idx]);

    free(cfg->client_config.servers);
    free(cfg);
}

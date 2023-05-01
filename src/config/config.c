#include "config.h"
#include "../logging/logger.h"

#include <libconfig.h>
#include <stdlib.h>
#include <malloc.h>

struct bentolibc_config * bentolibc_load_config(void)
{
    logger_info("Loading config");
    config_t * cfg = malloc(sizeof(config_t));
    struct bentolibc_config * config = malloc(sizeof(struct bentolibc_config));

    if (config_read_file(cfg, "/etc/bentolibc/bentolibc.conf") == CONFIG_FALSE)
    {
        logger_error("Failed to read configuration: %s, at %d in %s", cfg->error_text, cfg->error_line, cfg->error_file);
        abort();
    }
    config_lookup_string(cfg, "postgresql.url", (const char **) &(config->postgresql_config.url));
    config_lookup_string(cfg, "postgresql.user", (const char **) &(config->postgresql_config.username));
    config_lookup_string(cfg, "postgresql.pass", (const char **) &(config->postgresql_config.password));
    config_lookup_string(cfg, "postgresql.database", (const char **) &(config->postgresql_config.database));
    config_lookup_string(cfg, "storage", (const char **) &(config->storage_dir));
    logger_debug("Config loaded with: url=%s, user=%s, pass=%s, db=%s, dir=%s", config->postgresql_config.url, config->postgresql_config.username, config->postgresql_config.password, config->postgresql_config.database, config->storage_dir);

    config_destroy(cfg);

    free(cfg);
    logger_info("Config loading completed");
}

void bentolibc_destroy_config(struct bentolibc_config * cfg)
{
    free(cfg);
}

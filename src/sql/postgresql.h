#ifndef BENTOLIBC_POSTGRESQL_H
#define BENTOLIBC_POSTGRESQL_H

#include "../config/config.h"

struct postgresql_session;

struct postgresql_session * bentolibc_init_sql(struct bentolibc_postgresql_config * conf);

void bentolibc_destroy_sql(struct postgresql_session * session);

#endif //BENTOLIBC_POSTGRESQL_H

#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "command/dispatcher.h"
#include "config/config.h"

void normal_function(int argc, char ** argv)
{
    int a = 114514;
    int *b = &a;
    *b = 1919810;
    ck_assert_int_eq(a, 1919810);
}

START_TEST(command_dispatcher)
{
    struct command_dispatcher * dispatcher = bentolibc_create_dispatcher();
    struct command_info normal_cmd = { .name = "normal", .func = normal_function };
    bentolibc_register_command(dispatcher, &normal_cmd);

    char * normal_request[] = { "normal" };
    bentolibc_dispatch_command(dispatcher, 1, normal_request);

    bentolibc_destroy_dispatcher(dispatcher);
}
END_TEST

START_TEST(config)
{
    struct bentolibc_config * cfg = bentolibc_load_config();

    ck_assert_int_eq(cfg->version, 0);
    ck_assert_int_eq(cfg->server_config.enabled, true);
    ck_assert_str_eq(cfg->server_config.host, "0.0.0.0");
    ck_assert_int_eq(cfg->server_config.port, 3594);
    ck_assert_str_eq(cfg->server_config.postgresql_config.url, "unix:///run/postgresql/.s.PGSQL.5432");
    ck_assert_str_eq(cfg->server_config.postgresql_config.username, "bentolibc");
    ck_assert_str_eq(cfg->server_config.postgresql_config.password, "bentolibc");
    ck_assert_str_eq(cfg->server_config.postgresql_config.database, "bentolibc");
    ck_assert_int_eq(cfg->client_config.local, true);
    ck_assert_int_eq(cfg->client_config.share, true);
    ck_assert_str_eq(cfg->client_config.storage_dir, "/var/lib/bentolibc");
    ck_assert_str_eq(cfg->client_config.servers[0], "bentolibc.orangemc.moe");

    bentolibc_destroy_config(cfg);
}

TCase * craete_command_dispatcher_test_suite(void)
{
    TCase * result = tcase_create("command dispatcher test");
    tcase_add_test(result, command_dispatcher);
    return result;
}

TCase * create_config_test_suite(void)
{
    TCase * result = tcase_create("config test");
    tcase_add_test(result, config);
    return result;
}

int main(int argc, char ** argv)
{
    Suite * test_suite = suite_create("bentolibc");
    SRunner * s_runner = srunner_create(test_suite);

    suite_add_tcase(test_suite, craete_command_dispatcher_test_suite());
    suite_add_tcase(test_suite, create_config_test_suite());

    srunner_run_all(s_runner, CK_NORMAL);
    int failed_count = srunner_ntests_failed(s_runner);
    srunner_free(s_runner);

    return failed_count > 0;
}

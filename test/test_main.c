#include <check.h>
#include <signal.h>
#include <stdio.h>
#include "command/dispatcher.h"

void normal_function(int argc, char ** argv)
{
    int a = 114514;
    int *b = &a;
    *b = 1919810;
    ck_assert_int_eq(a, 1919810);
}

void errored_function(int argc, char ** argv)
{
    unsigned int *a = (unsigned int *)0x1145141919810233;
    *a = 0xdeadbeef;
    ck_assert_int_eq(*a, 0xdeadbeef);
}

START_TEST(command_dispatcher)
{
    struct command_dispatcher * dispatcher = bentolibc_create_dispatcher();
    struct command_info normal_cmd = { .name = "normal", .func = normal_function };
    struct command_info errored_cmd = { .name = "errored", .func = errored_function };
    bentolibc_register_command(dispatcher, &normal_cmd);
    bentolibc_register_command(dispatcher, &errored_cmd);

    char * normal_request[] = { "normal" };
    bentolibc_dispatch_command(dispatcher, 1, normal_request);
    ck_assert_int_eq(bentolibc_dispatcher_errno(dispatcher), OK);

    char * error_request[] = { "errored" };
    bentolibc_dispatch_command(dispatcher, 1, error_request);
    ck_assert_int_eq(bentolibc_dispatcher_errno(dispatcher), FAIL_MEMORY);

    bentolibc_destroy_dispatcher(dispatcher);
}
END_TEST

TCase * craete_command_dispatcher_test_suite(void)
{
    TCase * result = tcase_create("command dispatcher test");
    tcase_add_test(result, command_dispatcher);
    return result;
}

int main(int argc, char ** argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    Suite * test_suite = suite_create("bentolibc");
    SRunner * s_runner = srunner_create(test_suite);

    suite_add_tcase(test_suite, craete_command_dispatcher_test_suite());

    srunner_set_fork_status(s_runner, CK_NOFORK);
    srunner_run_all(s_runner, CK_NORMAL);
    int failed_count = srunner_ntests_failed(s_runner);
    srunner_free(s_runner);

    return failed_count > 0;
}

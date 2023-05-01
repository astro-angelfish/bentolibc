enable_testing()
find_package(Check REQUIRED)
include_directories(${CHECK_INCLUDE_DIRS})
link_directories(${CHECK_LIBRARY_DIRS})

set(TEST_SOURCES test_main.c)

add_executable(bentolibc_test ${TEST_SOURCES})
target_link_libraries(bentolibc_test bentolibc_common)
target_link_libraries(bentolibc_test check)

add_test(NAME bentolibc_test COMMAND bentolibc_test)

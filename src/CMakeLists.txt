
find_package(libconfig REQUIRED)

add_library(bentolibc_common logging/logger.c logging/logger.h config/config.c config/config.h command/dispatcher.c command/dispatcher.h command/command.h command/command.c sql/postgresql.c sql/postgresql.h elf/elfdump.c elf/elfdump.h
        elf/disassembler.c)

target_link_libraries(bentolibc_common hashmap.c)
target_link_libraries(bentolibc_common -lconfig)

target_include_directories(bentolibc_common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(bentolibc main.c)
target_link_libraries(bentolibc bentolibc_common)

install(TARGETS bentolibc DESTINATION /usr/bin COMPONENT binaries)
install(FILES bentolibc.cfg DESTINATION /etc/bentolibc COMPONENT config)

cmake_minimum_required(VERSION 3.26)
project(bentolibc C)

set(CMAKE_C_STANDARD 11)
include(CTest)

add_definitions(-D_GNU_SOURCE)

add_library(hashmap.c hashmap.c/hashmap.c)
add_library(fadec fadec/decode.c fadec/format.c)
execute_process(COMMAND python parseinstrs.py --32 decode instrs.txt fadec-decode-public-x86.inc fadec-decode-private-x86.inc WORKING_DIRECTORY fadec/)
execute_process(COMMAND python parseinstrs.py --64 decode instrs.txt fadec-decode-public-x64.inc fadec-decode-private-x64.inc WORKING_DIRECTORY fadec/)

add_subdirectory(src)
add_subdirectory(test)

cmake_minimum_required(VERSION 3.26)
project(bentolibc C)

set(CMAKE_C_STANDARD 11)
include(CTest)

add_definitions(-D_GNU_SOURCE)

add_library(hashmap.c hashmap.c/hashmap.c)

add_subdirectory(src)
add_subdirectory(test)

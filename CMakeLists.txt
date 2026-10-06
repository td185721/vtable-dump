cmake_minimum_required(VERSION 3.15)
project(vtable_dump CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(vtable-dump src/main.cpp)

if(MSVC)
    target_compile_options(vtable-dump PRIVATE /W4 /permissive-)
else()
    target_compile_options(vtable-dump PRIVATE -Wall -Wextra -Wpedantic)
endif()

cmake_minimum_required(VERSION 3.12)
project(Codename_Vision C)

set(CMAKE_C_STANDARD 11)

add_executable(vision
        bot/main.c)
add_executable(loader
        loader/src/binary.c
        loader/src/connection.c
        loader/src/main.c
        loader/src/server.c
        loader/src/telnet_info.c
        loader/src/util.c)

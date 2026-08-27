cmake_minimum_required(VERSION 3.16)
project(mayo C)

set(CMAKE_C_STANDARD 11)

add_executable(mayo
    Main.c
    Command.c
    Package.c
    Transport.c
)

target_link_libraries(mayo winhttp)

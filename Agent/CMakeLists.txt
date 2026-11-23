cmake_minimum_required(VERSION 3.16)
project(mayo C)

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
set(CMAKE_C_STANDARD 11)

add_executable(mayo WIN32
    Main.c
    Command.c
    Package.c
    Transport.c
    Resolve.c
    Evasion.c
    Syscall.c
    Unhook.c
)

target_link_libraries(mayo winhttp iphlpapi)

if (CMAKE_C_COMPILER MATCHES "mingw")
    target_link_options(mayo PRIVATE -mwindows)
endif()

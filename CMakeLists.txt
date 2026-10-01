cmake_minimum_required(VERSION 3.20)

project(SMIT5-1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT WIN32)
    message(FATAL_ERROR "Project must be built on Windows.")
endif()

add_compile_definitions(WIN32_LEAN_AND_MEAN NOMINMAX WIN32_NO_STATUS)

add_executable(SMIT5-1Server
    SMIT5-1.cpp
    SMIT5-1Server.cpp
    SMIT5-1Info.cpp
)
target_link_libraries(SMIT5-1Server PRIVATE ws2_32 mswsock bcrypt advapi32)

add_executable(SMIT5-1Client
    SMIT5-1Client.cpp
    SMIT5-1ClientNet.cpp
    SMIT5-1Display.cpp
)
target_link_libraries(SMIT5-1Client PRIVATE ws2_32 bcrypt advapi32)

if(MSVC)
    target_compile_options(SMIT5-1Server PRIVATE /W4 /permissive-)
    target_compile_options(SMIT5-1Client PRIVATE /W4 /permissive-)
endif()

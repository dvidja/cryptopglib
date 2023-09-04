cmake_minimum_required(VERSION 3.25)

project(cryptopglib)

set(CMAKE_CXX_STANDARD 23)

include_directories(include)


include(${CMAKE_BINARY_DIR}/conan_toolchain.cmake)

add_subdirectory(src build/src)
add_subdirectory(tests build/tests )

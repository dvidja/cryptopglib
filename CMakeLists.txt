cmake_minimum_required(VERSION 3.25)

project(cryptopglib)

set(CMAKE_CXX_STANDARD 17)


find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)

message("${OPENSSL_INCLUDE_DIR}")

add_subdirectory(src build/src)
add_subdirectory(tests build/tests )

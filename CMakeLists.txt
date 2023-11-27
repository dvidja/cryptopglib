cmake_minimum_required(VERSION 3.25)

project(cryptopglib)

set(CMAKE_CXX_STANDARD 20)

find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(BZip2 REQUIRED)

message("${ZLIB_LIBRARIES}")
message("${ZLIB_INCLUDE_DIRS}")
message("${OPENSSL_INCLUDE_DIR}")

add_subdirectory(src)
add_subdirectory(cryptopg_app)
add_subdirectory(cryptopg_rest_service)

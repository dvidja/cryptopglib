cmake_minimum_required(VERSION 3.25)

project(cryptopglib)

set(CMAKE_CXX_STANDARD 23)

include_directories(include)

add_subdirectory( src build/src )
#add_subdirectory( test build/tests )

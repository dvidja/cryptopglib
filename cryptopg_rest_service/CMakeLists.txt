project(cryptopg_rest_service)

# Add test cpp file
add_executable(cryptopg_rest_service cryptopg_rest_service.cpp
)

find_package(cpprestsdk REQUIRED)
if(NOT cpprestsdk_FOUND)
    message(FATAL_ERROR "cpprestsdk was not found")
endif()
message("CPPRESTSDK: ")
message("${cpprestsdk_INCLUDES}")

target_include_directories(cryptopg_rest_service
        PRIVATE
        ../include
)

target_link_libraries(cryptopg_rest_service
        PRIVATE
        cryptopglib
        cpprestsdk::cpprest
)

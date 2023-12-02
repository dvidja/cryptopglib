find_package(GTest REQUIRED)


add_executable(cryptopglib_tests
        cryptopglib_message_parser_tests.cpp
)

target_link_libraries(cryptopglib_tests
        PRIVATE
        GTest::GTest
        cryptopglib)

add_test(cryptopglib_gtests cryptopglib_tests)

configure_file(test_data/public_key.asc test_data/public_key.asc COPYONLY)

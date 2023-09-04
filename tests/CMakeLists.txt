project(tests)

# Add test cpp file
add_executable(runUnitTests cryptopg_tests.cpp)

target_link_libraries(runUnitTests cryptopglib)
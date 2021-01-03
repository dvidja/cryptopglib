project(tests)

# Add test cpp file
add_executable(runUnitTests main.cpp)

target_link_libraries(runUnitTests cryptopglib)
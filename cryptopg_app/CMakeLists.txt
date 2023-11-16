project(app)

# Add test cpp file
add_executable(cryptopg_app main.cpp)

target_link_libraries(cryptopg_app cryptopglib )
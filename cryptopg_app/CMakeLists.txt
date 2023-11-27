project(cryptopg_app)

# Add test cpp file
add_executable(cryptopg_app main.cpp
        model/pgp_key.cpp
        model/pgp_key_info.h
        model/utils.cpp
        model/utils.h)


FIND_PACKAGE( Boost COMPONENTS program_options REQUIRED )
if(NOT Boost_FOUND)
    message(FATAL_ERROR "Boost library was not found!")
endif()

include_directories(${Boost_INCLUDE_DIRS})
target_link_libraries(cryptopg_app PUBLIC
        ${Boost_LIBRARIES}
        cryptopglib
)
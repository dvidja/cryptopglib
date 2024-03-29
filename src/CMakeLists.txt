project(cryptopglib)

set (CRYPTOPGLIBSOURCES
        ${CRYPTOPGLIBSOURCES}
        cryptopg.cpp
        open_pgp_impl.cpp
        pgp_errors.cpp
        pgp_message_impl.cpp
        pgp_key.cpp
        pgp_message.cpp
)


add_library(cryptopglib STATIC ${CRYPTOPGLIBSOURCES})

add_subdirectory(crypto)
add_subdirectory(pgp_creator)
add_subdirectory(pgp_data)
add_subdirectory(pgp_parser)
add_subdirectory(utils)

target_include_directories(cryptopglib PUBLIC
        ../include
        ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(cryptopglib PUBLIC
        ${OPENSSL_CRYPTO_LIBRARY}
        ${ZLIB_LIBRARIES}
        ${BZIP2_LIBRARIES}
)


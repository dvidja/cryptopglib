project(cryptopglib)

set (CRYPTOPGLIBSOURCES
        ${CRYPTOPGLIBSOURCES}
        cryptopg.cpp
        OpenPGPImpl.cpp
        PGPErrors.cpp
        PGPMessageImpl.cpp
        )


add_library(cryptopglib STATIC ${CRYPTOPGLIBSOURCES})

add_subdirectory(Crypto)
add_subdirectory(PGPCreator)
add_subdirectory(PGPData)
add_subdirectory(PGPParser)
add_subdirectory(Utils)

target_include_directories(cryptopglib PUBLIC
        ../include
        "${OPENSSL_INCLUDE_DIR}")

target_link_libraries(cryptopglib PUBLIC OPENSSL_CRYPTO_LIBRARY)


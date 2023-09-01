project(cryptopglib)

set (CRYPTOPGLIBSOURCES
        ${CRYPTOPGLIBSOURCES}
        cryptopg.cpp
        OpenPGPImpl.cpp
        PGPErrors.cpp
        PGPMessageImpl.cpp
        )

add_subdirectory(Crypto)
add_subdirectory(PGPCreator)
add_subdirectory(PGPData)
add_subdirectory(PGPParser)
add_subdirectory(Utils)

add_library(cryptopglib STATIC ${CRYPTOPGLIBSOURCES})
find_package(OpenSSL REQUIRED)
target_link_libraries(cryptopglib openssl::openssl)


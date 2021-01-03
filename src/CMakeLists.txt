project(cryptopglib)

set (CRYPTOPGLIBSOURCES
        ${CRYPTOPGLIBSOURCES}
        PGPErrors.cpp
        cryptopg.cpp
        Utils/base64.cpp
        Utils/crc24.cpp
        Utils/DataBuffer.cpp
        )

add_library( cryptopglib STATIC ${CRYPTOPGLIBSOURCES})


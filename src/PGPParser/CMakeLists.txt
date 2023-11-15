
target_sources(cryptopglib PUBLIC
        PGPMessageParser.cpp
        PGPPacketsParser.cpp
        PGPParser.cpp
)

add_subdirectory(PacketParsers)

target_sources(cryptopglib PUBLIC
        pgp_message_parser.cpp
        pgp_packets_parser.cpp
        pgp_parser.cpp
)

add_subdirectory(packet_parsers)
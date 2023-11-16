
target_sources(cryptopglib PUBLIC
        compressed_data_packet_parser.cpp
        literal_data_packet_parser.cpp
        marker_packet_parser.cpp
        modification_detection_code_packet_parser.cpp
        one_pass_signature_packet_parser.cpp
        packet_parser.cpp
        public_key_encrypted_packet_parser.cpp
        public_key_packet_parser.cpp
        secret_key_packet_parser.cpp
        signature_packet_parser.cpp
        symmetrically_encrypted_data_packet_parser.cpp
        symmetric_key_encrypted_session_key_packet_parser.cpp
        trust_packet_parser.cpp
        user_attribute_packet_parser.cpp
        user_id_packetP_parser.cpp
)
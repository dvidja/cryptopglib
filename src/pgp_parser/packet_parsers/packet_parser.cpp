//
//  PacketParser.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 10.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//


#include "packet_parser.h"
#include "public_key_encrypted_packet_parser.h"
#include "signature_packet_parser.h"
#include "symmetric_key_encrypted_session_key_packet_parser.h"
#include "one_pass_signature_packet_parser.h"
#include "secret_key_packet_parser.h"
#include "public_key_packet_parser.h"
#include "compressed_data_packet_parser.h"
#include "symmetrically_encrypted_data_packet_parser.h"
#include "marker_packet_parser.h"
#include "literal_data_packet_parser.h"
#include "trust_packet_parser.h"
#include "user_id_packetP_parser.h"
#include "user_attribute_packet_parser.h"
#include "modification_detection_code_packet_parser.h"


namespace cryptopglib::pgp_parser::packet_parsers {
    PacketParser::~PacketParser() {

    }

    int GetPacketLengthForPartialContent(ParsingDataBuffer &data_buffer, bool &partial) {
        char hdr[8]; // ????
        int hdrlen = 0;
        int data_part_length = 0;

        int c = data_buffer.GetNextByte();

        if (c == -1) {
            // TODO : handle error
            return 0;
        }

        hdr[hdrlen++] = c;
        if (c < 192) {
            partial = false;
            data_part_length = c;
        } else if (c < 224) {
            partial = false;
            data_part_length = (c - 192) * 256;

            if ((c = data_buffer.GetNextByte()) == -1) {
                // TODO : handle error
                return 0;
            }

            hdr[hdrlen++] = c;
            data_part_length += c + 192;
        } else if (c == 255) {
            partial = false;
            data_part_length = (hdr[hdrlen++] = data_buffer.GetNextByteNotEOF()) << 24;
            data_part_length |= (hdr[hdrlen++] = data_buffer.GetNextByteNotEOF()) << 16;
            data_part_length |= (hdr[hdrlen++] = data_buffer.GetNextByteNotEOF()) << 8;

            if ((c = data_buffer.GetNextByte()) == -1) {
                //TODO: handle error
                return 0;
            }

            data_part_length |= (hdr[hdrlen++] = c);
        } else {
            partial = true;
            data_part_length = 1 << (c & 0x1f);
        }

        return data_part_length;
    }

    std::unique_ptr<PacketParser> GetPacketParser(PacketType packet_type) {
        switch (packet_type) {
            case PacketType::kNone:
                return nullptr;
            case PacketType::kPublicKeyEncryptedPacket:
                return std::make_unique<PublicKeyEncryptedPacketParser>();
            case PacketType::kSignaturePacket:
                return std::make_unique<SignaturePacketParser>();
            case PacketType::kSymmetricKeyEncryptedSessionKeyPacket:
                return std::make_unique<SymmetricKeyEncryptedSessionKeyPacketParser>();
            case PacketType::kOnePassSignaturePacket:
                return std::make_unique<OnePassSignaturePacketParser>();
            case PacketType::kSecretKeyPacket:
                return std::make_unique<SecretKeyPacketParser>();
            case PacketType::kPublicKeyPacket:
                return std::make_unique<PublicKeyPacketParser>();
            case PacketType::kSecretSubkeyPacket:
                return std::make_unique<SecretKeyPacketParser>();
            case PacketType::kCompressedDataPacket:
                return std::make_unique<CompressedDataPacketParser>();
            case PacketType::kSymmetricallyEncryptedDataPacket:
                return std::make_unique<SymmetricallyEncryptedDataPacketParser>();
            case PacketType::kMarkerPacket:
                return std::make_unique<MarkerPacketParser>();
            case PacketType::kLiteralDataPacket:
                return std::make_unique<LiteralDataPacketParser>();
            case PacketType::kTrustPacket:
                return std::make_unique<TrustPacketParser>();
            case PacketType::kUserIDPacket:
                return std::make_unique<UserIDPacketParser>();
            case PacketType::kPublicSubkeyPacket:
                return std::make_unique<PublicKeyPacketParser>();
            case PacketType::kUserAttributePacket:
                return std::make_unique<UserAttributePacketParser>();
            case PacketType::kSymmetricEncryptedAndIntegrityProtectedDataPacket:
                return std::make_unique<SymmetricallyEncryptedDataPacketParser>(true);
            case PacketType::kModificationDetectionCodePacket:
                return std::make_unique<ModificationDetectionCodePacketParser>();
            default:
                return nullptr;
        }
    }
}

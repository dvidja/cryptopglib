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
        std::unique_ptr<PacketParser> packet_parser(nullptr);

        switch (packet_type) {
            case PacketType::kNone:
                throw (std::exception()); // todo: generate correct error
            case PacketType::kPublicKeyEncryptedPacket:
                packet_parser = std::make_unique<PublicKeyEncryptedPacketParser>();
                break;
            case PacketType::kSignaturePacket:
                packet_parser = std::make_unique<SignaturePacketParser>();
                break;
            case PacketType::kSymmetricKeyEncryptedSessionKeyPacket:
                packet_parser = std::make_unique<SymmetricKeyEncryptedSessionKeyPacketParser>();
                break;
            case PacketType::kOnePassSignaturePacket:
                packet_parser = std::make_unique<OnePassSignaturePacketParser>();
                break;
            case PacketType::kSecretKeyPacket:
                packet_parser = std::make_unique<SecretKeyPacketParser>();
                break;
            case PacketType::kPublicKeyPacket:
                packet_parser = std::make_unique<PublicKeyPacketParser>();
                break;
            case PacketType::kSecretSubkeyPacket:
                packet_parser = std::make_unique<SecretKeyPacketParser>();
                break;
            case PacketType::kCompressedDataPacket:
                packet_parser = std::make_unique<CompressedDataPacketParser>();
                break;
            case PacketType::kSymmetricallyEncryptedDataPacket:
                packet_parser = std::make_unique<SymmetricallyEncryptedDataPacketParser>();
                break;
            case PacketType::kMarkerPacket:
                packet_parser = std::make_unique<MarkerPacketParser>();
                break;
            case PacketType::kLiteralDataPacket:
                packet_parser = std::make_unique<LiteralDataPacketParser>();
                break;
            case PacketType::kTrustPacket:
                packet_parser = std::make_unique<TrustPacketParser>();
                break;
            case PacketType::kUserIDPacket:
                packet_parser = std::make_unique<UserIDPacketParser>();
                break;
            case PacketType::kPublicSubkeyPacket:
                packet_parser = std::make_unique<PublicKeyPacketParser>();
                break;
            case PacketType::kUserAttributePacket:
                packet_parser = std::make_unique<UserAttributePacketParser>();
                break;
            case PacketType::kSymmetricEncryptedAndIntegrityProtectedDataPacket:
                packet_parser = std::make_unique<SymmetricallyEncryptedDataPacketParser>(true);
                break;
            case PacketType::kModificationDetectionCodePacket:
                packet_parser = std::make_unique<ModificationDetectionCodePacketParser>();
                break;
            default:
                throw (std::exception()); // todo: generate correct exceprion
        }

        return packet_parser;
    }
}

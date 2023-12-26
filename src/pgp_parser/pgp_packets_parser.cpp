//
//  PGPPacketsParser.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 18.4.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "pgp_packets_parser.h"

#include "packet_parsers/public_key_encrypted_packet_parser.h"
#include "packet_parsers/signature_packet_parser.h"
#include "packet_parsers/public_key_packet_parser.h"
#include "packet_parsers/secret_key_packet_parser.h"
#include "packet_parsers/user_id_packetP_parser.h"
#include "packet_parsers/symmetrically_encrypted_data_packet_parser.h"
#include "packet_parsers/compressed_data_packet_parser.h"
#include "packet_parsers/literal_data_packet_parser.h"
#include "packet_parsers/symmetric_key_encrypted_session_key_packet_parser.h"
#include "packet_parsers/one_pass_signature_packet_parser.h"
#include "packet_parsers/marker_packet_parser.h"
#include "packet_parsers/trust_packet_parser.h"
#include "packet_parsers/user_attribute_packet_parser.h"
#include "packet_parsers/modification_detection_code_packet_parser.h"

#include "cryptopglib/pgp_errors.h"

namespace {
    bool IsCorrectFirstBit(const unsigned char& c) // first bit always must be 1
    {
        return (c & 0x80);
    }

    //return TRUE if new format of packet presented
    bool GetPacketFormat(const unsigned char& c)
    {
        return (c & 0x40);
    }

    cryptopglib::PacketType GetPacketType(const unsigned char& c, bool packet_format)
    {
        if (packet_format) // new packet format
        {
            return (cryptopglib::PacketType)(c & 0x3F);
        }

        return (cryptopglib::PacketType)((c >> 2) & 0xF);
    }

    std::tuple<unsigned long, bool> GetPacketLengthNewFormat(const unsigned char& ctb, cryptopglib::ParsingDataBuffer& parsingData)
    {
        unsigned char hdr[8]; // ????
        int hdrlen = 0;
        auto packet_type = static_cast<cryptopglib::PacketType>(ctb & 0x3f);
        unsigned char c = parsingData.GetNextByte();

        unsigned long packetLength = 0;
        bool partial = false;

        hdr[hdrlen++] = c;
        if (c < 192)
        {
            packetLength = c;
        }
        else if (c < 224)
        {
            packetLength = (c - 192) * 256;
            if (!parsingData.HasNextByte()) {
                //todo: throw an error
                return {};
            }
            c = parsingData.GetNextByte();
            hdr[hdrlen++] = c;
            packetLength += c + 192;
        }
        else if (c == 255)
        {
            packetLength = parsingData.GetNextByteNotEOF() << 24;
            packetLength |= parsingData.GetNextByteNotEOF() << 16;
            packetLength |= parsingData.GetNextByteNotEOF() << 8;
            packetLength |= parsingData.GetNextByteNotEOF();
        }
        else /* Partial body length.  */
        {
            switch (packet_type)
            {
                case cryptopglib::PacketType::kLiteralDataPacket:
                case cryptopglib::PacketType::kSymmetricallyEncryptedDataPacket:
                case cryptopglib::PacketType::kSymmetricEncryptedAndIntegrityProtectedDataPacket:
                case cryptopglib::PacketType::kCompressedDataPacket:
                    partial = true;
                    packetLength = c;
                    break;

                default:
                    //TODO: throw an error
                    return {};
            }
        }

        return std::make_tuple(packetLength, partial);
    }

    std::tuple<unsigned long, bool> GetPacketLengthOldFormat(const unsigned char& ctb, cryptopglib::ParsingDataBuffer& parsingData)
    {
        // Get Packet tag
        auto packet_type = static_cast<cryptopglib::PacketType>((ctb >> 2) & 0xf);

        // Get Packet Length
        unsigned long packetLength = 0;
        bool partial = false;

        int lenbytes = ((ctb & 3) == 3) ? 0 : (1 << (ctb & 3));
        if (!lenbytes)
        {
            packetLength = 0;	/* Don't know the value.  */
            /* This isn't really partial, but we can treat it the same
             in a "read until the end" sort of way.  */
            partial = true;

            if (packet_type != cryptopglib::PacketType::kSymmetricallyEncryptedDataPacket
                && packet_type != cryptopglib::PacketType::kLiteralDataPacket
                && packet_type != cryptopglib::PacketType::kCompressedDataPacket)
            {
                //TODO: thrown an error
                return {};
            }
        }
        else
        {
            for (; lenbytes; lenbytes--)
            {
                packetLength <<= 8;
                packetLength |= parsingData.GetNextByte();
            }
        }

        return std::make_tuple(packetLength, partial);
    }

    std::tuple<unsigned long, bool> GetPacketLength(const unsigned char& c, cryptopglib::ParsingDataBuffer& parsingData, bool packetFormat)
    {
        if (packetFormat) // new packet format
        {
            return GetPacketLengthNewFormat(c, parsingData);
        }

        return GetPacketLengthOldFormat(c, parsingData);
    }

    std::unique_ptr<cryptopglib::pgp_data::PGPPacket> ParsePacket(cryptopglib::ParsingDataBuffer& parsingData,
                                                                  cryptopglib::PacketType packet_type,
                                                                  unsigned long packet_length,
                                                                  bool partial) {
        std::unique_ptr<cryptopglib::pgp_parser::packet_parsers::PacketParser> packet_parser
            = cryptopglib::pgp_parser::packet_parsers::GetPacketParser(packet_type);

        if (packet_parser) {
            std::unique_ptr<cryptopglib::pgp_data::PGPPacket> packet;
            /*if (partial) {
                packet = packet_parser->Parse(data_buffer_, partial, static_cast<int>(packet_length));
            } else {
                DataBuffer temp_buffer(data_buffer_.GetRange(packet_length));
                packet = packet_parser->Parse(temp_buffer, partial, 0);
            }

            if (packet != nullptr) {
                packets_.push_back(std::shared_ptr<PGPPacket>(packet));
            }*/
        } else {
            //SkipPacket(packet_length, partial);
        }

        return nullptr;
    }

    std::unique_ptr<cryptopglib::pgp_data::PGPPacket> ParsePacket(cryptopglib::ParsingDataBuffer& parsingData) {
        if (!parsingData.HasNextByte()) {
            return nullptr;
        }

        auto c = parsingData.GetNextByte();
        if (!IsCorrectFirstBit(c)) {
            throw (PGPError(PACKAGE_FIRST_BYTE_ERROR));
        }

        bool packetFormat = GetPacketFormat(c);
        cryptopglib::PacketType packetType = GetPacketType(c, packetFormat);

        auto [packetLength, partial] = GetPacketLength(c, parsingData, packetFormat);

        return ParsePacket(parsingData, packetType, packetLength, partial);
    }
}

namespace cryptopglib::pgp_parser {
    std::vector<std::unique_ptr<pgp_data::PGPPacket>>ParsePackets(std::vector<unsigned char>& data) {
        std::vector<std::unique_ptr<pgp_data::PGPPacket>> packets;

        cryptopglib::ParsingDataBuffer parsingData(data);
        while (parsingData.HasNextByte()) {
            try {
                auto packet = ParsePacket(parsingData);
                packets.push_back(std::move(packet));
            }
            catch (PGPError &exp) {
                std::cout << exp.what();
            }
        }

        return packets;
    }
}




/// next the old


namespace
{
    using namespace cryptopglib;
    using namespace pgp_data::packets;
    using namespace pgp_parser::packet_parsers;

    int GetPacketLengthNewFormat(const unsigned char& ctb, ParsingDataBuffer& data_buffer, unsigned long& packet_length, bool& partial)
    {
        packet_length = 0;
        char hdr[8]; // ????
        int hdrlen = 0;

        // Get Packet tag
        PacketType packet_type = (PacketType)(ctb & 0x3f);

        // Get Packet Length

        int c = data_buffer.GetNextByte();

        if (c == -1)
        {
            return 1;
        }

        hdr[hdrlen++] = c;
        if (c < 192)
        {
            packet_length = c;
        }
        else if (c < 224)
        {
            packet_length = (c - 192) * 256;
            if ((c = data_buffer.GetNextByte()) == -1)
            {
                return 1;
            }

            hdr[hdrlen++] = c;
            packet_length += c + 192;
        }
        else if (c == 255)
        {
            packet_length = data_buffer.GetNextByteNotEOF() << 24;
            packet_length |= data_buffer.GetNextByteNotEOF() << 16;
            packet_length |= data_buffer.GetNextByteNotEOF() << 8;
            packet_length |= data_buffer.GetNextByteNotEOF();
        }
        else /* Partial body length.  */
        {
            switch (packet_type)
            {
                case PacketType::kLiteralDataPacket:
                case PacketType::kSymmetricallyEncryptedDataPacket:
                case PacketType::kSymmetricEncryptedAndIntegrityProtectedDataPacket:
                case PacketType::kCompressedDataPacket:
                    partial = true;
                    packet_length = c;
                    break;

                default:
                    return 1;
            }
        }

        return 0;
    }

    int GetPacketLengthOldFormat(const unsigned char& ctb, ParsingDataBuffer& data_buffer, unsigned long& packet_length, bool& partial)
    {
        // Get Packet tag
        PacketType packet_type = (PacketType)((ctb >> 2) & 0xf);

        // Get Packet Length

        int lenbytes = ((ctb & 3) == 3) ? 0 : (1 << (ctb & 3));
        if (!lenbytes)
        {
            packet_length = 0;	/* Don't know the value.  */
            /* This isn't really partial, but we can treat it the same
             in a "read until the end" sort of way.  */
            partial = true;

            if (packet_type != PacketType::kSymmetricallyEncryptedDataPacket && packet_type != PacketType::kLiteralDataPacket && packet_type != PacketType::kCompressedDataPacket)
            {
                return 1;
            }
        }
        else
        {
            for (; lenbytes; lenbytes--)
            {
                packet_length <<= 8;
                packet_length |= data_buffer.GetNextByte();
            }
        }

        return 0;
    }
    
    int GetPacketLength(const unsigned char& c, ParsingDataBuffer& data_buffer, bool packet_format, unsigned long& packet_length, bool& partial)
    {
        if (packet_format) // new packet format
        {
            return GetPacketLengthNewFormat(c, data_buffer, packet_length, partial);
        }

        return GetPacketLengthOldFormat(c, data_buffer, packet_length, partial);
    }
}

namespace cryptopglib::pgp_parser {
    PGPPacketsParserOLD::PGPPacketsParserOLD(const CharDataVector &data)
            : data_buffer_(data) {

    }

    PGPPacketsArray PGPPacketsParserOLD::ParsePackets() {
        while (data_buffer_.HasNextByte()) {
            try {
                ParsePacket();
            }
            catch (PGPError &exp) {
                std::cout << exp.what();
            }
        }

        return packets_;
    }

    void PGPPacketsParserOLD::GetUserIDPacketsRawData(CharDataVector &user_id_data, const int user_id_number) {
        data_buffer_.ResetCurrentPosition();
        if (data_buffer_.IsEmpty()) {
            return;
        }

        int current_user_id_number = 0;

        while (data_buffer_.HasNextByte()) {
            size_t start_pos = data_buffer_.CurrentPosition();
            unsigned char c = data_buffer_.GetNextByte();

            if (!IsCorrectFirstBit(c)) {
                throw (PGPError(PACKAGE_FIRST_BYTE_ERROR));
            }

            bool packet_format = GetPacketFormat(c);

            PacketType packet_type = GetPacketType(c, packet_format);

            bool partial = false;
            unsigned long packet_length = 0;
            int error = GetPacketLength(c, data_buffer_, packet_format, packet_length, partial);
            if (error != 0) {
                throw (PGPError(PACKAGE_LENGTH_ERROR));
            }

            if (packet_type != PacketType::kUserIDPacket) {
                data_buffer_.Skip(packet_length);
            } else {
                if (user_id_number == current_user_id_number) {
                    CharDataVector temp_data(
                            data_buffer_.GetRangeOld(start_pos, data_buffer_.CurrentPosition() + packet_length));
                    //CharDataVector temp_data(data_buffer_.GetRange(start_pos, data_buffer_.current_position() + packet_length));
                    user_id_data.push_back(0xB4);
                    user_id_data.push_back((packet_length >> 24) & 0xFF);
                    user_id_data.push_back((packet_length >> 16) & 0xFF);
                    user_id_data.push_back((packet_length >> 8) & 0xFF);
                    user_id_data.push_back(packet_length & 0xFF);

                    user_id_data.insert(user_id_data.end(), temp_data.begin(), temp_data.end());
                    current_user_id_number++;
                } else {
                    data_buffer_.Skip(packet_length);
                }
            }
        }
    }

    void PGPPacketsParserOLD::GetKeyPacketsRawData(CharDataVector &key_data, const int key_number) {
        data_buffer_.ResetCurrentPosition();
        if (data_buffer_.IsEmpty()) {
            return;
        }

        int current_key_number = 0;

        while (data_buffer_.HasNextByte()) {
            //size_t start_pos = data_buffer_.current_position();
            unsigned char c = data_buffer_.GetNextByte();

            if (!IsCorrectFirstBit(c)) {
                throw (PGPError(PACKAGE_FIRST_BYTE_ERROR));
            }

            bool packet_format = GetPacketFormat(c);

            PacketType packet_type = GetPacketType(c, packet_format);

            bool partial = false;
            unsigned long packet_length = 0;
            int error = GetPacketLength(c, data_buffer_, packet_format, packet_length, partial);
            if (error != 0) {
                throw (PGPError(PACKAGE_LENGTH_ERROR));
            }

            if ((packet_type != PacketType::kPublicKeyPacket) && (packet_type != PacketType::kPublicSubkeyPacket)
                && (packet_type != PacketType::kSecretKeyPacket) && (packet_type != PacketType::kSecretSubkeyPacket)) {
                data_buffer_.Skip(packet_length);
            } else {
                if (key_number == current_key_number) {
                    //CharDataVector temp_data(data_buffer_.GetRange(start_pos, data_buffer_.current_position() + packet_length));
                    CharDataVector temp_data(data_buffer_.GetRangeOld(packet_length));

                    key_data.push_back(0x99);
                    key_data.push_back((packet_length >> 8) & 0xFF);
                    key_data.push_back(packet_length & 0xFF);

                    key_data.insert(key_data.end(), temp_data.begin(), temp_data.end());
                } else {
                    data_buffer_.Skip(packet_length);
                }
            }
        }
    }

    void PGPPacketsParserOLD::GetV4HashedSignatureData(CharDataVector &signature_data, const int signature_number) {
        data_buffer_.ResetCurrentPosition();
        if (data_buffer_.IsEmpty()) {
            return;
        }

        int current_signature_number = 0;

        while (data_buffer_.HasNextByte()) {
            unsigned char c = data_buffer_.GetNextByte();

            if (!IsCorrectFirstBit(c)) {
                throw (PGPError(PACKAGE_FIRST_BYTE_ERROR));
            }

            bool packet_format = GetPacketFormat(c);

            PacketType packet_type = GetPacketType(c, packet_format);

            bool partial = false;
            unsigned long packet_length = 0;
            int error = GetPacketLength(c, data_buffer_, packet_format, packet_length, partial);
            if (error != 0) {
                throw (PGPError(PACKAGE_LENGTH_ERROR));
            }

            if (packet_type != PacketType::kSignaturePacket) {
                data_buffer_.Skip(packet_length);
            } else {
                if (signature_number == current_signature_number) {
                    size_t start_pos = data_buffer_.CurrentPosition();

                    if (data_buffer_.GetNextByte() != 4) {
                        // error isn't v4 packet
                        return;
                    }

                    data_buffer_.GetNextByteNotEOF(); // signature class
                    data_buffer_.GetNextByteNotEOF();// public key algorithm
                    data_buffer_.GetNextByteNotEOF();///hash algorithm

                    int n = data_buffer_.GetNextTwoOctets();
                    if (n > 10000) {
                        // TODO: handle error "signature packet: hashed data too long;
                        return;
                    }
                    if (n) {
                        //Hashed subpacket data
                        data_buffer_.GetRangeOld(n);
                    }
                    size_t last_pos = data_buffer_.CurrentPosition();

                    CharDataVector temp_data(data_buffer_.GetRangeOld(start_pos, last_pos));
                    //CharDataVector temp_data(data_buffer_.GetRange(packet_length));
                } else {
                    data_buffer_.Skip(packet_length);
                }
            }

        }
    }

    void PGPPacketsParserOLD::ParsePacket() {
        if (data_buffer_.IsEmpty()) {
            return;
        }

        unsigned char c = data_buffer_.GetNextByte();

        if (!IsCorrectFirstBit(c)) {
            throw (PGPError(PACKAGE_FIRST_BYTE_ERROR));
        }

        bool packet_format = GetPacketFormat(c);

        PacketType packet_type = GetPacketType(c, packet_format);

        bool partial = false;
        unsigned long packet_length = 0;
        int error = GetPacketLength(c, data_buffer_, packet_format, packet_length, partial);
        if (error != 0) {
            throw (PGPError(PACKAGE_LENGTH_ERROR));
        }

        ParsePacket(packet_type, packet_length, partial);

        return;
    }

    void PGPPacketsParserOLD::ParsePacket(PacketType packet_type, unsigned long packet_length, bool partial) {
        std::unique_ptr<PacketParser> packet_parser = CreatePacketParser(packet_type);
        if (packet_parser) {
            PGPPacket *packet = nullptr;
            if (partial) {
                packet = packet_parser->Parse(data_buffer_, partial, static_cast<int>(packet_length));
            } else {
                ParsingDataBuffer temp_buffer(data_buffer_.GetRangeOld(packet_length));
                packet = packet_parser->Parse(temp_buffer, partial, 0);
            }

            if (packet != nullptr) {
                packets_.push_back(std::shared_ptr<PGPPacket>(packet));
            }
        } else {
            SkipPacket(packet_length, partial);
        }

        return;
    }

    void PGPPacketsParserOLD::SkipPacket(unsigned long packet_length, bool partial) {
        if (partial) {
            data_buffer_.Skip(data_buffer_.RestLength());

            return;
        }

        data_buffer_.Skip(packet_length);
    }

    std::unique_ptr<PacketParser> PGPPacketsParserOLD::CreatePacketParser(PacketType packet_type) {
        std::unique_ptr<PacketParser> packet_parser(nullptr);

        switch (packet_type) {
            case PacketType::kNone:
                throw (PGPError(PACKAGE_UNKNOWN_TYPE));
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
                throw (PGPError(PACKAGE_UNKNOWN_TYPE));
        }

        return packet_parser;
    }
}

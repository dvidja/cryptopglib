//
//  PGPPacketsParser.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 18.4.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "PGPPacketsParser.h"

#include "PacketParsers/PublicKeyEnctyptedPacketParser.h"
#include "PacketParsers/SignaturePacketParser.h"
#include "PacketParsers/PublicKeyPacketParser.h"
#include "PacketParsers/SecretKeyPacketParser.h"
#include "PacketParsers/UserIDPacketParser.h"
#include "PacketParsers/SymmetricallyEncryptedDataPacketParser.h"
#include "PacketParsers/CompressedDataPacketParser.h"
#include "PacketParsers/LiteralDataPacketParser.h"
#include "PacketParsers/SymmetricKeyEncryptedSessionKeyPacketParser.h"
#include "PacketParsers/OnePassSignaturePacketParser.h"
#include "PacketParsers/MarkerPacketParser.h"
#include "PacketParsers/TrustPacketParser.h"
#include "PacketParsers/UserAttributePacketParser.h"
#include "PacketParsers/ModificationDetectionCodePacketParser.h"

#include "cryptopglib/PGPErrors.h"


namespace
{
    bool IsCorrectFirstBit(const unsigned char& c) // first bit always must be 1
    {
        return (c & 0x80);
    }
    
    //return TRUE if new format of packet presented
    bool GetPacketFormat(const unsigned char& c)
    {
        return (c & 0x40);
    }
    
    int GetPacketType(const unsigned char& c, bool packet_format)
    {
        if (packet_format) // new packet format
        {
            return c & 0x3F;
        }
        
        return (c >> 2) & 0xF;
    }
    
    int GetPacketLengthNewFormat(const unsigned char& ctb, DataBuffer& data_buffer, unsigned long& packet_length, bool& partial)
    {
        packet_length = 0;
        char hdr[8]; // ????
        int hdrlen = 0;
        
        // Get Packet tag
        int packet_type = ctb & 0x3f;
        
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
                case PT_LITERAL_DATA_PACKET:
                case PT_SYMMETRICALLY_ENCRYPTED_DATA_PACKET:
                case PT_SYMMETRIC_ENCRYTPED_AND_INTEGRITY_PROTECTED_DATA_PACKET:
                case PT_COMPRESSED_DATA_PACKET:
                    partial = true;
                    packet_length = c;
                    break;
                    
                default:
                    return 1;
            }
        }

        return 0;
    }
    
    int GetPacketLengthOldFormat(const unsigned char& ctb, DataBuffer& data_buffer, unsigned long& packet_length, bool& partial)
    {
        // Get Packet tag
        int packet_type = (ctb >> 2) & 0xf;
                
        // Get Packet Length
        
        int lenbytes = ((ctb & 3) == 3) ? 0 : (1 << (ctb & 3));
        if (!lenbytes)
        {
            packet_length = 0;	/* Don't know the value.  */
            /* This isn't really partial, but we can treat it the same
             in a "read until the end" sort of way.  */
            partial = true;
            
            if (packet_type != PT_SYMMETRICALLY_ENCRYPTED_DATA_PACKET && packet_type != PT_LITERAL_DATA_PACKET && packet_type != PT_COMPRESSED_DATA_PACKET)
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
    
    int GetPacketLength(const unsigned char& c, DataBuffer& data_buffer, bool packet_format, unsigned long& packet_length, bool& partial)
    {
        if (packet_format) // new packet format
        {
            return GetPacketLengthNewFormat(c, data_buffer, packet_length, partial);
        }
        
        return GetPacketLengthOldFormat(c, data_buffer, packet_length, partial);
    }
}


PGPPacketsParser::PGPPacketsParser(const CharDataVector &data)
    : data_buffer_(data)
{
    
}

PGPPacketsArray PGPPacketsParser::ParsePackets()
{
    while(data_buffer_.HasNextByte())
    {
        try
        {
            ParsePacket();
        }
        catch (PGPError& exp)
        {
            std::cout << exp.what();
        }
    }
    
    return packets_;
}

void PGPPacketsParser::GetUserIDPacketsRawData(CharDataVector& user_id_data, const int user_id_number)
{
    data_buffer_.ResetCurrentPosition();
    if (data_buffer_.empty())
    {
        return;
    }
    
    int current_user_id_number = 0;
    
    while (data_buffer_.HasNextByte())
    {
        size_t start_pos = data_buffer_.current_position();
        unsigned char c = data_buffer_.GetNextByte();
        
        if (!IsCorrectFirstBit(c))
        {
            throw (PGPError(PACKAGE_FIRST_BYTE_ERROR));
        }

        bool packet_format = GetPacketFormat(c);
        
        int packet_type = GetPacketType(c, packet_format);
        
        bool partial = false;
        unsigned long packet_length = 0;
        int error = GetPacketLength(c, data_buffer_, packet_format, packet_length, partial);
        if (error != 0)
        {
            throw (PGPError(PACKAGE_LENGTH_ERROR));
        }
        
        if (packet_type != PT_USER_ID_PACKET)
        {
            data_buffer_.Skip(packet_length);
        }
        else
        {
            if (user_id_number == current_user_id_number)
            {
                CharDataVector temp_data(data_buffer_.GetRange(start_pos, data_buffer_.current_position() + packet_length));
                //CharDataVector temp_data(data_buffer_.GetRange(start_pos, data_buffer_.current_position() + packet_length));
                user_id_data.push_back(0xB4);
                user_id_data.push_back((packet_length >> 24) & 0xFF);
                user_id_data.push_back((packet_length >> 16) & 0xFF);
                user_id_data.push_back((packet_length >> 8) & 0xFF);
                user_id_data.push_back(packet_length & 0xFF);

                user_id_data.insert(user_id_data.end(), temp_data.begin(), temp_data.end());
                current_user_id_number++;
            }
            else
            {
                data_buffer_.Skip(packet_length);
            }
        }
    }

    return;
}

void PGPPacketsParser::GetKeyPacketsRawData(CharDataVector& key_data, const int key_number)
{
    data_buffer_.ResetCurrentPosition();
    if (data_buffer_.empty())
    {
        return;
    }
    
    int current_key_number = 0;
    
    while (data_buffer_.HasNextByte())
    {
        //size_t start_pos = data_buffer_.current_position();
        unsigned char c = data_buffer_.GetNextByte();
        
        if (!IsCorrectFirstBit(c))
        {
            throw (PGPError(PACKAGE_FIRST_BYTE_ERROR));
        }
        
        bool packet_format = GetPacketFormat(c);
        
        int packet_type = GetPacketType(c, packet_format);
        
        bool partial = false;
        unsigned long packet_length = 0;
        int error = GetPacketLength(c, data_buffer_, packet_format, packet_length, partial);
        if (error != 0)
        {
            throw (PGPError(PACKAGE_LENGTH_ERROR));
        }
        
        if ((packet_type != PT_PUBLIC_KEY_PACKET) && (packet_type != PT_PUBLIC_SUBKEY_PACKET)
            && (packet_type != PT_SECRET_KEY_PACKET) && (packet_type != PT_SECRET_SUBKEY_PACKET))
        {
            data_buffer_.Skip(packet_length);
        }
        else
        {
            if(key_number == current_key_number)
            {
                //CharDataVector temp_data(data_buffer_.GetRange(start_pos, data_buffer_.current_position() + packet_length));
                CharDataVector temp_data(data_buffer_.GetRange(packet_length));
                
                key_data.push_back(0x99);
                key_data.push_back((packet_length >> 8) & 0xFF);
                key_data.push_back(packet_length & 0xFF);
                
                key_data.insert(key_data.end(), temp_data.begin(), temp_data.end());
            }
            else
            {
                data_buffer_.Skip(packet_length);    
            }
        }
    }
    
    return;
}

void PGPPacketsParser::GetV4HashedSignatureData(CharDataVector& signature_data, const int signature_number)
{
    data_buffer_.ResetCurrentPosition();
    if (data_buffer_.empty())
    {
        return;
    }
    
    int current_signature_number = 0;
    
    while (data_buffer_.HasNextByte())
    {
        unsigned char c = data_buffer_.GetNextByte();
        
        if (!IsCorrectFirstBit(c))
        {
            throw (PGPError(PACKAGE_FIRST_BYTE_ERROR));
        }
        
        bool packet_format = GetPacketFormat(c);
        
        int packet_type = GetPacketType(c, packet_format);
        
        bool partial = false;
        unsigned long packet_length = 0;
        int error = GetPacketLength(c, data_buffer_, packet_format, packet_length, partial);
        if (error != 0)
        {
            throw (PGPError(PACKAGE_LENGTH_ERROR));
        }
        
        if (packet_type != PT_SIGNATURE_PACKET)
        {
            data_buffer_.Skip(packet_length);
        }
        else
        {
            if(signature_number == current_signature_number)
            {
                size_t start_pos = data_buffer_.current_position();
                
                if (data_buffer_.GetNextByte() != 4)
                {
                    // error isn't v4 packet
                    return;
                }
                
                data_buffer_.GetNextByteNotEOF(); // signature class
                data_buffer_.GetNextByteNotEOF();// public key algorithm
                data_buffer_.GetNextByteNotEOF();///hash algorithm
                
                int n = data_buffer_.GetNextTwoOctets();
                if (n > 10000)
                {
                    // TODO: handle error "signature packet: hashed data too long;
                    return ;
                }
                if (n)
                {
                    //Hashed subpacket data
                    data_buffer_.GetRange(n);
                }
                size_t last_pos = data_buffer_.current_position();
                
                CharDataVector temp_data(data_buffer_.GetRange(start_pos, last_pos));
                //CharDataVector temp_data(data_buffer_.GetRange(packet_length));
            }
            else
            {
                data_buffer_.Skip(packet_length);
            }
        }

    }

    
    return;
}

void PGPPacketsParser::ParsePacket()
{
    if (data_buffer_.empty())
    {
        return;
    }

    unsigned char c = data_buffer_.GetNextByte();
    
    if (!IsCorrectFirstBit(c))
    {
        throw (PGPError(PACKAGE_FIRST_BYTE_ERROR));
    }
    
    bool packet_format = GetPacketFormat(c);
    
    int packet_type = GetPacketType(c, packet_format);
    
    bool partial = false;
    unsigned long packet_length = 0;
    int error = GetPacketLength(c, data_buffer_, packet_format, packet_length, partial);
    if (error != 0)
    {
        throw (PGPError(PACKAGE_LENGTH_ERROR));
    }
    
    ParsePacket(packet_type, packet_length, partial);
    
    return;
}

void PGPPacketsParser::ParsePacket(int packet_type, unsigned long packet_length, bool partial)
{
    std::unique_ptr<PacketParser> packet_parser = CreatePacketParser(packet_type);
    if (packet_parser)
    {
        PGPPacket* packet = nullptr;
        if (partial)
        {
            packet = packet_parser->Parse(data_buffer_, partial, static_cast<int>(packet_length));
        }
        else
        {
            DataBuffer temp_buffer(data_buffer_.GetRange(packet_length));
            packet = packet_parser->Parse(temp_buffer, partial);
        }
        
        if (packet != nullptr)
        {
            packets_.push_back(std::shared_ptr<PGPPacket>(packet));
        }
    }
    else
    {
        SkipPacket(packet_length, partial);
    }
    
    return;
}

void PGPPacketsParser::SkipPacket(unsigned long packet_length, bool partial)
{
    if (partial)
    {
        data_buffer_.Skip(data_buffer_.rest_length());
        
        return;
    }
    
    data_buffer_.Skip(packet_length);
}

std::unique_ptr<PacketParser> PGPPacketsParser::CreatePacketParser(int packet_type)
{
    std::unique_ptr<PacketParser> packet_parser(nullptr);
    
    switch (packet_type)
    {
        case PT_NONE:
            throw (PGPError(PACKAGE_UNKNOWN_TYPE));
            break;
        case PT_PUBLIC_KEY_ENCRYPTED_PACKET:
            packet_parser = std::make_unique<PublicKeyEnctyptedPacketParser>();
            break;
        case PT_SIGNATURE_PACKET:
            packet_parser = std::make_unique<SignaturePacketParser>();
            break;
        case PT_SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY_PACKET:
            packet_parser = std::make_unique<SymmetricKeyEncryptedSessionKeyPacketParser>();
            break;
        case PT_ONE_PASS_SIGNATURE_PACKET:
            packet_parser = std::make_unique<OnePassSignaturePacketParser>();
            break;
        case PT_SECRET_KEY_PACKET:
            packet_parser = std::make_unique<SecretKeyPacketParser>();
            break;
        case PT_PUBLIC_KEY_PACKET:
            packet_parser = std::make_unique<PublicKeyPacketParser>();
            break;
        case PT_SECRET_SUBKEY_PACKET:
            packet_parser = std::make_unique<SecretKeyPacketParser>();
            break;
        case PT_COMPRESSED_DATA_PACKET:
            packet_parser = std::make_unique<CompressedDataPacketParser>();
            break;
        case PT_SYMMETRICALLY_ENCRYPTED_DATA_PACKET:
            packet_parser = std::make_unique<SymmetricallyEncryptedDataPacketParser>();
            break;
        case PT_MARKER_PACKET:
            packet_parser = std::make_unique<MarkerPacketParser>();
            break;
        case PT_LITERAL_DATA_PACKET:
            packet_parser = std::make_unique<LiteralDataPacketParser>();
            break;
        case PT_TRUST_PACKET:
            packet_parser = std::make_unique<TrustPacketParser>();
            break;
        case PT_USER_ID_PACKET:
            packet_parser = std::make_unique<UserIDPacketParser>();
            break;
        case PT_PUBLIC_SUBKEY_PACKET:
            packet_parser = std::make_unique<PublicKeyPacketParser>();
            break;
        case PT_USER_ATTRIBUTE_PACKET:
            packet_parser = std::make_unique<UserAttributePacketParser>();
            break;
        case PT_SYMMETRIC_ENCRYTPED_AND_INTEGRITY_PROTECTED_DATA_PACKET:
            packet_parser = std::make_unique<SymmetricallyEncryptedDataPacketParser>(true);
            break;
        case PT_MODIFICATION_DETECTION_CODE_PACKET:
            packet_parser = std::make_unique<ModificationDetectionCodePacketParser>();
            break;
        default:
            throw (PGPError(PACKAGE_UNKNOWN_TYPE));
    }
    
    return packet_parser;
}

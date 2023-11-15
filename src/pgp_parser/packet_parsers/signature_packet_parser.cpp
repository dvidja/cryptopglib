//
//  SignaturePacketParser.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 1.5.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "signature_packet_parser.h"
#include "../../Crypto/public_key_algorithms.h"
#include "../../Crypto/hash_algorithms.h"
#include "../../Crypto/symmetric_key_algorithms.h"
#include "../../Crypto/compression_algorithms.h"


SignaturePacket* SignaturePacketParser::Parse(DataBuffer& data_buffer, bool partial, int c)
{
    if (data_buffer.rest_length() < 16)
    {
        //TODO : handle error
        return nullptr;
    }
    
    int version = data_buffer.GetNextByteNotEOF();

    if ((version < 2) || (version > 5))
    {
        // TODO: handle error
        return nullptr;
    }
    
    if (version == 4)
    {
        return ParseV4Packet(data_buffer, partial);
    }
    else
    {
        return ParseV3Packet(data_buffer, partial);
    }

    return nullptr;
}

SignaturePacket* SignaturePacketParser::ParseV3Packet(DataBuffer& data_buffer, bool partial)
{
	SignaturePacket* packet = new SignaturePacket(3);
    
    packet->SetExpiredSignatureTime(0);
    
    int md5_length = data_buffer.GetNextByteNotEOF();
    if (md5_length != 5)
    {
        //TODO: handle error
    }
    
    int signature_class = data_buffer.GetNextByteNotEOF();
	packet->SetSignatureType(signature_class);
    
    unsigned int creation_time = data_buffer.GetNextFourOctets();
	packet->SetCreationTime(creation_time);

	KeyIDData key_id(2);
    key_id[0] = data_buffer.GetNextFourOctets();
    key_id[1] = data_buffer.GetNextFourOctets();
	packet->SetKeyID(key_id);
    
    PublicKeyAlgorithms public_key_algorithm = static_cast<PublicKeyAlgorithms>(data_buffer.GetNextByteNotEOF());
	packet->SetPublicKeyAlgorithm(public_key_algorithm);
    
    HashAlgorithms digest_algorithm = static_cast<HashAlgorithms>(data_buffer.GetNextByteNotEOF());
	packet->SetHashAlgorithm(digest_algorithm);
    
    if (data_buffer.rest_length() < 5)
    {
        //TODO: handle error
        return nullptr;
    }
    
	std::vector<int> digest_start(2);
    digest_start[0] = data_buffer.GetNextByteNotEOF();
    digest_start[1] = data_buffer.GetNextByteNotEOF();

	packet->SetDigestStart(digest_start);
    
    switch (public_key_algorithm)
    {
        case PKA_RSA:
        case PKA_RSA_SIGN_ONLY:
            {
                int l = data_buffer.GetNextTwoOctets();
                l = (l + 7) / 8;
            
                CharDataVector mpi_data = data_buffer.GetRange(l);
                packet->AddMPI(mpi_data);
            }
            return packet;
            
        case PKA_DSA:
            {
                // !!! for DSA we read all data
                CharDataVector mpis = data_buffer.GetRange(data_buffer.rest_length());
                packet->AddMPI(mpis);
            }
            return packet;
            
        default:
            break;
    }

    data_buffer.GetRange(data_buffer.rest_length());
    
    return nullptr;
}

SignaturePacket* SignaturePacketParser::ParseV4Packet(DataBuffer& data_buffer, bool partial)
{
    SignaturePacket* packet = new SignaturePacket(4);
    
    int signature_class = data_buffer.GetNextByteNotEOF();
    packet->SetSignatureType(signature_class);
    packet->SetExpiredSignatureTime(0);

    PublicKeyAlgorithms public_key_algorithm = static_cast<PublicKeyAlgorithms>(data_buffer.GetNextByteNotEOF());
    packet->SetPublicKeyAlgorithm(public_key_algorithm);

    HashAlgorithms digest_algorithm = static_cast<HashAlgorithms>(data_buffer.GetNextByteNotEOF());
    packet->SetHashAlgorithm(digest_algorithm);
     
    int n = data_buffer.GetNextTwoOctets();
    if (n > 10000)
    {
        // TODO: handle error "signature packet: hashed data too long;
        return nullptr;
    }
    if (n)
    {
        //Hashed subpacket data
        ParseSubpacket(data_buffer.GetRange(n), packet, true);
    }
    
    n = data_buffer.GetNextTwoOctets();
    if (n > 10000)
    {
        //TODO: handle error "signature packet: unhashed data too long
        return nullptr;
    }
    if (n)
    {
        // Unhashed subpasket data
        ParseSubpacket(data_buffer.GetRange(n), packet, false);
    }
    
    if (data_buffer.rest_length() < 5)
    {
        //TODO: handle error
        return nullptr;
    }
    
    std::vector<int> digest_start(2);
    digest_start[0] = data_buffer.GetNextByteNotEOF();
    digest_start[1] = data_buffer.GetNextByteNotEOF();
    
    packet->SetDigestStart(digest_start);
    
    switch (public_key_algorithm)
    {
        case PKA_RSA:
            {
                int l = data_buffer.GetNextTwoOctets();
                l = (l + 7) / 8;
            
                CharDataVector mpi_data = data_buffer.GetRange(l);
                packet->AddMPI(mpi_data);                
            }
            return packet;
            
        case PKA_DSA:
            {
                // !!! for DSA we read all data
                CharDataVector mpis = data_buffer.GetRange(data_buffer.rest_length());
                packet->AddMPI(mpis);
            }
            return packet;
            
        default:
            break;
    }
    
    data_buffer.GetRange(data_buffer.rest_length());

    return nullptr;
}

void SignaturePacketParser::ParseSubpacket(DataBuffer data_buffer, SignaturePacket* packet, bool hashed)
{   
    if (data_buffer.length() < 2)
    {
        return;
    }
    
    int subpacket_length = 0;
    int n = data_buffer.GetNextByte();
    if (n < 192)
    {
        subpacket_length = n;
    }
    if ((n >= 192) && (n < 255))
    {
        subpacket_length = ((n - 192) << 8) + data_buffer.GetNextByte() + 192;
    }
    if (n == 255)
    {
        subpacket_length = data_buffer.GetNextFourOctets();
    }
    
    SignatureSubpacketType subpacket_type = static_cast<SignatureSubpacketType>(data_buffer.GetNextByte());
    
    switch (subpacket_type)
    {
        case SST_ISSUER:
            {
                CharDataVector subpacket_data = data_buffer.GetRange(subpacket_length - 1);
                if (subpacket_data.size() != 8)
                {
                    break;
                }
                
                KeyIDData key_id(2);
                key_id[0] = 0;
                key_id[1] = 0;
                
                key_id[0] = subpacket_data[0] << 24;
                key_id[0] |= subpacket_data[1] << 16;
                key_id[0] |= subpacket_data[2] << 8;
                key_id[0] |= subpacket_data[3];
                
                key_id[1] = subpacket_data[4] << 24;
                key_id[1] |= subpacket_data[5] << 16;
                key_id[1] |= subpacket_data[6] << 8;
                key_id[1] |= subpacket_data[7];

                packet->SetKeyID(key_id);
            }
            break;
        case SST_SIGNATURE_CREATION_TIME:
            {
                CharDataVector subpacket_data = data_buffer.GetRange(subpacket_length - 1);
                if (subpacket_data.size() != 4)
                {
                    break;
                }
                
                unsigned int creation_time = 0;
                creation_time = subpacket_data[0] << 24;
                creation_time |= subpacket_data[1] << 16;
                creation_time |= subpacket_data[2] << 8;
                creation_time |= subpacket_data[3];
                
                packet->SetCreationTime(creation_time);
            }
            break;
        case SST_EMBEDDED_SIGNATURE:
            {
                DataBuffer subpacket_data(data_buffer.GetRange(subpacket_length - 1));
                packet->AddSubpacketData(subpacket_type, subpacket_data.GetRawData(), hashed);
                SignaturePacketParser embeded_signature_parser;
                embeded_signature_parser.Parse(subpacket_data, false, 0);
            }
            break;
        case SST_KEY_EXPIRATION_TIME:
            {
                DataBuffer subpacket_data(data_buffer.GetRange(subpacket_length - 1));
                packet->AddSubpacketData(subpacket_type, subpacket_data.GetRawData(), hashed);
                
                if (subpacket_data.length() != 4)
                {
                    break;
                }
                
                unsigned int expired_time = subpacket_data.GetNextFourOctets();
                packet->SetExpiredKeyTime(expired_time);
            }
            break;
        case SST_SIGNATURE_EXPIRATION_TIME:
            {
                DataBuffer subpacket_data(data_buffer.GetRange(subpacket_length - 1));
                packet->AddSubpacketData(subpacket_type, subpacket_data.GetRawData(), hashed);
                
                if (subpacket_data.length() != 4)
                {
                    break;
                }
                
                unsigned int expired_time = subpacket_data.GetNextFourOctets();
                packet->SetExpiredSignatureTime(expired_time);
            }
            break;
        case SST_PREFERRED_HASH_ALGO:
            {
                DataBuffer subpacket_data(data_buffer.GetRange(subpacket_length - 1));
                packet->AddSubpacketData(subpacket_type, subpacket_data.GetRawData(), hashed);
                
                std::vector<HashAlgorithms> prefered_hash_algo;
                for (int i = 0; i < subpacket_data.length(); ++i)
                {
                    char t = subpacket_data.GetNextByte();
                    prefered_hash_algo.push_back(static_cast<HashAlgorithms>(t));
                }
                
                packet->SetPreferedHahAlgos(prefered_hash_algo);
            }
            break;
        case SST_PREFERRED_SYMMETRIC_ALGO:
            {
                DataBuffer subpacket_data(data_buffer.GetRange(subpacket_length - 1));
                packet->AddSubpacketData(subpacket_type, subpacket_data.GetRawData(), hashed);
                
                std::vector<SymmetricKeyAlgorithms> prefered_chiper_algo;
                for (int i = 0; i < subpacket_data.length(); ++i)
                {
                    char t = subpacket_data.GetNextByte();
                    prefered_chiper_algo.push_back(static_cast<SymmetricKeyAlgorithms>(t));
                }
                
                packet->SetPreferedChiperAlgos(prefered_chiper_algo);
            }
            break;
        case SST_PREFERRED_COMPRESSION_ALGO:
            {
                DataBuffer subpacket_data(data_buffer.GetRange(subpacket_length - 1));
                packet->AddSubpacketData(subpacket_type, subpacket_data.GetRawData(), hashed);
                
                std::vector<CompressionAlgorithms> prefered_compression_algo;
                for (int i = 0; i < subpacket_data.length(); ++i)
                {
                    char t = subpacket_data.GetNextByte();
                    prefered_compression_algo.push_back(static_cast<CompressionAlgorithms>(t));
                }
                
                packet->SetPreferedCompressionAlgos(prefered_compression_algo);
            }
            break;
            
        default:
            packet->AddSubpacketData(subpacket_type, data_buffer.GetRange(subpacket_length - 1), hashed);
            break;
    }
    
    if (data_buffer.rest_length() != 0)
    {
        ParseSubpacket(data_buffer.GetRange(data_buffer.rest_length()), packet, hashed);
    }
}

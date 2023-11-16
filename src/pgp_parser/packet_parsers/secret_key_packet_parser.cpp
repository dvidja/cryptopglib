//
//  SecretKeyPacketParser.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 1.5.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "secret_key_packet_parser.h"
#include "public_key_packet_parser.h"
#include "../../pgp_data/packets/public_key_packet.h"
#include "../../crypto/public_key_algorithms.h"
#include "../../crypto/symmetric_key_algorithms.h"

namespace
{
    size_t GetMPIDataLength(DataBuffer& data_buffer)
    {
        int l = data_buffer.GetNextTwoOctets();
        l = (l + 7) / 8;
        
        return l;
    }
    
    int ReadEachMPIseparately(DataBuffer& data_buffer, SecretKeyPacket* packet, PublicKeyAlgorithms algo)
    {
        switch (algo)
        {
            case PKA_RSA:
            case PKA_RSA_ENCRYPT_ONLY:
            case PKA_RSA_SIGN_ONLY:
                {
                    size_t length = GetMPIDataLength(data_buffer);
                    packet->AddMPI(data_buffer.GetRange(length));
                    
                    length = GetMPIDataLength(data_buffer);
                    packet->AddMPI(data_buffer.GetRange(length));
                    
                    length = GetMPIDataLength(data_buffer);
                    packet->AddMPI(data_buffer.GetRange(length));
                    
                    length = GetMPIDataLength(data_buffer);
                    packet->AddMPI(data_buffer.GetRange(length));
                }
                break;
            case PKA_ELGAMAL:
            case PKA_DSA:
                {
                    size_t length = GetMPIDataLength(data_buffer);
                    packet->AddMPI(data_buffer.GetRange(length));
                }
                break;
                
            default:
                return 1;
        }
        
        return 0;
    }
}


SecretKeyPacket* SecretKeyPacketParser::Parse(DataBuffer& data_buffer, bool partial, int c)
{
    PublicKeyPacketParser pub_key_parser;
    PublicKeyPacketPtr pub_key_packet(reinterpret_cast<PublicKeyPacket*>(pub_key_parser.Parse(data_buffer, false, c)));
    
    if(pub_key_packet == nullptr)
    {
        return nullptr;
    }
    
    SecretKeyPacket* secret_key_packet = new SecretKeyPacket(pub_key_packet);

    int string_to_key_usage = data_buffer.GetNextByte();
    secret_key_packet->SetStringToKeyUsage(string_to_key_usage);

    if ((string_to_key_usage == 254) || (string_to_key_usage == 255))
    {
        SymmetricKeyAlgorithms symetric_encrypting_algo = static_cast<SymmetricKeyAlgorithms>(data_buffer.GetNextByte());
        secret_key_packet->SetSymmetricKeyAlgorithm(symetric_encrypting_algo);
        
        int string_to_key_specifier_type = data_buffer.GetNextByte();
        secret_key_packet->SetStringToKeySpecefier(string_to_key_specifier_type);
        
        HashAlgorithms hash_algorithm = static_cast<HashAlgorithms>(data_buffer.GetNextByte());
        secret_key_packet->SetStringToKeyHashAlgorithm(hash_algorithm);
        
        switch (string_to_key_specifier_type)
        {
            case 0: // simple s2k
                {
                    break;
                }
            case 1://salted s2k
                {
                    CharDataVector salt_value = data_buffer.GetRange(8);
                    secret_key_packet->SetSaltValue(salt_value);
                    
                    break;
                }
            case 3://iterated and salted
                {
                    CharDataVector salt_value = data_buffer.GetRange(8);
                    secret_key_packet->SetSaltValue(salt_value);
                    
                    unsigned int count = data_buffer.GetNextByte();
                    secret_key_packet->SetCount(count);
                    
                    break;
                }
            default:
                break;
        }
    }
    else if (string_to_key_usage != 0)
    {
        SymmetricKeyAlgorithms symetric_encrypting_algo = static_cast<SymmetricKeyAlgorithms>(data_buffer.GetNextByte());
        secret_key_packet->SetSymmetricKeyAlgorithm(symetric_encrypting_algo);
    }
    
    if (string_to_key_usage != 0)
    {
        std::shared_ptr<crypto::SymmetricKeyAlgorithm>symmetric_key_algo_impl(crypto::GetSymmetricKeyAlgorithm(secret_key_packet->GetSymmetricKeyAlgorithm()));

        int length = symmetric_key_algo_impl != nullptr ? symmetric_key_algo_impl->GetCipherBlockSize() : 0;
        if (length != 0)
        {
            CharDataVector initial_vector = data_buffer.GetRange(length);
            if (initial_vector.size() == length)
            {
                secret_key_packet->SetInitialVector(initial_vector);
            }
        }
    }
    
    if (string_to_key_usage == 0)
    {
        ReadEachMPIseparately(data_buffer, secret_key_packet, pub_key_packet->GetPublicKeyAlgorithm());
    }
    else
    {
        int key_version = pub_key_packet->GetKeyVersion();
        
        if (key_version == 3)
        {
            //data is encrypted
            ReadEachMPIseparately(data_buffer, secret_key_packet, pub_key_packet->GetPublicKeyAlgorithm());
        }
        
        if (key_version == 4)
        {
            // encrypted all rest data
            secret_key_packet->AddMPI(data_buffer.GetRange(data_buffer.rest_length()));
            
            //other data extract after decryption
            return secret_key_packet;
        }
    }
        
    if (string_to_key_usage == 254)
    {
        CharDataVector sha_hash = data_buffer.GetRange(20);
    }
    else
    {
        CharDataVector checksum = data_buffer.GetRange(2);
    }
    
    return secret_key_packet;
}
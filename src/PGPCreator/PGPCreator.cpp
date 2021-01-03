//
//  PGPCreator.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 28.7.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "PGPCreator.h"
#include "../PGPData/Packets/SignaturePacket.h"
#include "../PGPData/Packets/MarkerPacket.h"

#include "../Utils/base64.h"
#include "../Utils/crc24.h"

#include <cmath>

namespace
{
    double log2(double n)
    {
        return log(n) / log(2.0);
    }

    void PushStringToData(const std::string& str, CharDataVector& data)
    {
        data.insert(data.end(), str.begin(), str.end());
        data.push_back('\r');
        data.push_back('\n');
    }
    
    void GetKeyIDData(const KeyIDData& key_id, CharDataVector& key_id_data)
    {
        key_id_data.clear();
        
        key_id_data.push_back((key_id[0] >> 24) & 0xFF);
        key_id_data.push_back((key_id[0] >> 16) & 0xFF);
        key_id_data.push_back((key_id[0] >> 8) & 0xFF);
        key_id_data.push_back(key_id[0] & 0xFF);
        
        key_id_data.push_back((key_id[1] >> 24) & 0xFF);
        key_id_data.push_back((key_id[1] >> 16) & 0xFF);
        key_id_data.push_back((key_id[1] >> 8) & 0xFF);
        key_id_data.push_back(key_id[1] & 0xFF);
    }
    
    void GetPacketData(SignaturePacketPtr packet, CharDataVector& data)
    {        
        CharDataVector signature_data;
        packet->GetBinaryData(signature_data);
        
        data.insert(data.end(), signature_data.begin(), signature_data.end());        
    }
    
    std::string GetHashInfoString(PGPMessagePtr message_impl)
    {
        PGPPacketsArray packets = message_impl->GetPackets();

        for(auto iter = packets.begin(); iter != packets.end(); ++iter)
        {
            if ((*iter)->GetPacketType() == PT_SIGNATURE_PACKET)
            {
                SignaturePacketPtr sig_packet = std::dynamic_pointer_cast<SignaturePacket>(*iter);
                
                crypto::HashAlgorithmPtr hash_algo_impl = crypto::GetHashImpl(sig_packet->GetHashAlgorithm());
                std::string hash_info("Hash:" + hash_algo_impl->GetHashAlgorithmName());
                
                return hash_info;
            }
        }
        
        return "";
    }
    
    bool GetBinaryRepresentationOfSignatureMessage(PGPMessagePtr message_impl, CharDataVector& data, bool armored)
    {
        if (armored)
        {
            PushStringToData("-----BEGIN PGP SIGNED MESSAGE-----", data);
            std::string hash_info(GetHashInfoString(message_impl));

            if (!hash_info.empty())
            {
                PushStringToData(hash_info, data);
            }

            PushStringToData("", data);
            
            PushStringToData(message_impl->GetPlainText(), data);
        }

        PushStringToData("-----BEGIN PGP SIGNATURE-----", data);
        // add data
        
        PushStringToData("", data);
        CharDataVector signature_packet_data;
        SignaturePacketPtr signature_packet = std::dynamic_pointer_cast<SignaturePacket>(message_impl->GetPackets()[0]);
        GetPacketData(signature_packet, signature_packet_data);
        
        std::string base64_data = Utils::Base64Encode(signature_packet_data);
        
        {
            size_t rest_length = base64_data.length();
            size_t writing_length = 0;
            while (rest_length > 64)
            {
                PushStringToData(std::string(base64_data.begin() + writing_length, base64_data.begin() + writing_length + 64), data);
                writing_length += 64;
                rest_length -= 64;
            }
            
            PushStringToData(std::string(base64_data.begin() + writing_length, base64_data.end()), data);
            
        }
        
        long crc = Utils::CRC24(signature_packet_data);
        
        CharDataVector crc_data;
        crc_data.push_back((crc >> 16) & 0xFF);
        crc_data.push_back((crc >> 8) & 0xFF);
        crc_data.push_back(crc & 0xFF);
        
        std::string str_crc = Utils::Base64Encode(crc_data);
        data.push_back('=');
        PushStringToData(str_crc, data);

        PushStringToData("-----END PGP SIGNATURE-----", data);

        return true;
    }
        
    bool GetBinaryRepresentationOfEncryptedMessage(PGPMessagePtr message_ptr, CharDataVector& data)
    {
        PushStringToData("-----BEGIN PGP MESSAGE-----", data);
        PushStringToData("", data);
        
        CharDataVector temp_data;
        
        for (auto iter = message_ptr->GetPackets().begin(); iter != message_ptr->GetPackets().end(); ++iter)
        {
            if ((*iter) == nullptr)
            {
                data.empty();
                return false;
            }
            
            CharDataVector packet_data;
            (*iter)->GetBinaryData(packet_data);
            
            temp_data.insert(temp_data.end(), packet_data.begin(), packet_data.end());
        }
        
        std::string base64_data = Utils::Base64Encode(temp_data);
        
        {
            size_t rest_length = base64_data.length();
            size_t writing_length = 0;
            while (rest_length > 64)
            {
                PushStringToData(std::string(base64_data.begin() + writing_length, base64_data.begin() + writing_length + 64), data);
                writing_length += 64;
                rest_length -= 64;
            }
            
            PushStringToData(std::string(base64_data.begin() + writing_length, base64_data.end()), data);
            
        }
        
        long crc = Utils::CRC24(temp_data);
        
        CharDataVector crc_data;
        crc_data.push_back((crc >> 16) & 0xFF);
        crc_data.push_back((crc >> 8) & 0xFF);
        crc_data.push_back(crc & 0xFF);
        
        std::string str_crc = Utils::Base64Encode(crc_data);
        data.push_back('=');
        PushStringToData(str_crc, data);

        
        PushStringToData("-----END PGP MESSAGE-----", data);
        
        return true;
    }
    
    bool GetBinaryRepresentationOfPublicKeyMessage(PGPMessagePtr message_ptr, CharDataVector& data)
    {
        PushStringToData("-----BEGIN PGP PUBLIC KEY BLOCK-----", data);
        PushStringToData("", data);

        CharDataVector temp_data;
        
        for (auto iter = message_ptr->GetPackets().begin(); iter != message_ptr->GetPackets().end(); ++iter)
        {
            if ((*iter) == nullptr)
            {
                data.empty();
                return false;
            }

            CharDataVector packet_data;
            (*iter)->GetBinaryData(packet_data);
            
            temp_data.insert(temp_data.end(), packet_data.begin(), packet_data.end());
        }
        
        std::string base64_data = Utils::Base64Encode(temp_data);
        
        {
            size_t rest_length = base64_data.length();
            size_t writing_length = 0;
            while (rest_length > 64)
            {
                PushStringToData(std::string(base64_data.begin() + writing_length, base64_data.begin() + writing_length + 64), data);
                writing_length += 64;
                rest_length -= 64;
            }
            
            PushStringToData(std::string(base64_data.begin() + writing_length, base64_data.end()), data);
            
        }
        
        long crc = Utils::CRC24(temp_data);
        
        CharDataVector crc_data;
        crc_data.push_back((crc >> 16) & 0xFF);
        crc_data.push_back((crc >> 8) & 0xFF);
        crc_data.push_back(crc & 0xFF);
        
        std::string str_crc = Utils::Base64Encode(crc_data);
        data.push_back('=');
        PushStringToData(str_crc, data);
        
        
        PushStringToData("-----END PGP PUBLIC KEY BLOCK-----", data);
        
        return true;
    }
    
    bool GetBinaryRepresentationOfPrivateKeyMessage(PGPMessagePtr message_ptr, CharDataVector& data)
    {
        PushStringToData("-----BEGIN PGP PRIVATE KEY BLOCK-----", data);
        PushStringToData("", data);
        
        CharDataVector temp_data;
        
        for (auto iter = message_ptr->GetPackets().begin(); iter != message_ptr->GetPackets().end(); ++iter)
        {
            if ((*iter) == nullptr)
            {
                data.empty();
                return false;
            }

            CharDataVector packet_data;
            (*iter)->GetBinaryData(packet_data);
            
            temp_data.insert(temp_data.end(), packet_data.begin(), packet_data.end());
        }
        
        std::string base64_data = Utils::Base64Encode(temp_data);
        
        {
            size_t rest_length = base64_data.length();
            size_t writing_length = 0;
            while (rest_length > 64)
            {
                PushStringToData(std::string(base64_data.begin() + writing_length, base64_data.begin() + writing_length + 64), data);
                writing_length += 64;
                rest_length -= 64;
            }
            
            PushStringToData(std::string(base64_data.begin() + writing_length, base64_data.end()), data);
        }
        
        long crc = Utils::CRC24(temp_data);
        
        CharDataVector crc_data;
        crc_data.push_back((crc >> 16) & 0xFF);
        crc_data.push_back((crc >> 8) & 0xFF);
        crc_data.push_back(crc & 0xFF);
        
        std::string str_crc = Utils::Base64Encode(crc_data);
        data.push_back('=');
        PushStringToData(str_crc, data);
        
        
        PushStringToData("-----END PGP PRIVATE KEY BLOCK-----", data);
        
        return true;
    }
}

bool PGPCreator::GetBinaryRepresentationOfMessage(PGPMessagePtr message_impl, CharDataVector& data, bool armored)
{
    switch (message_impl->GetMessageType())
    {
        case MT_CRYPTO_MESSAGE:
            return GetBinaryRepresentationOfEncryptedMessage(message_impl, data);
            break;
        case MT_PRIVATE_KEY:
            return GetBinaryRepresentationOfPrivateKeyMessage(message_impl, data);
            break;
        case MT_PUBLIC_KEY:
            return GetBinaryRepresentationOfPublicKeyMessage(message_impl, data);
            break;
        case MT_SIGNED_MESSAGE:
            return GetBinaryRepresentationOfSignatureMessage(message_impl, data, armored);
            break;
        default:
            break;
    }
    
    return true;
}


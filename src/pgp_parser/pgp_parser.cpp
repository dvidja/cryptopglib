//
//  PGPParser.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 22.4.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "pgp_parser.h"

#include "../pgp_data/packets/signature_packet.h"
#include "../pgp_data/packets/public_key_packet.h"
#include "../pgp_data/packets/secret_key_packet.h"
#include "../pgp_data/packets/user_id_packet.h"
#include "../crypto/pgp_signature.h"


namespace cryptopglib::pgp_parser {
    bool IsKeySigned(const PGPPacketsArray& packets)
    {
        for (auto iter = packets.begin(); iter != packets.end(); ++iter)
        {
            if ((*iter)->GetPacketType() == PT_SIGNATURE_PACKET)
            {
                return true;
            }
        }
        
        return false;
    }
    
    crypto::PublicKeyPacketPtr GetPublicKeyByID(const PGPPacketsArray& packets, const KeyIDData& key_id)
    {
        for (auto iter = packets.begin(); iter != packets.end(); ++iter)
        {
            if (((*iter)->GetPacketType() == PT_PUBLIC_KEY_PACKET) || ((*iter)->GetPacketType() == PT_PUBLIC_SUBKEY_PACKET))
            {
                crypto::PublicKeyPacketPtr public_key_packet_ptr = std::dynamic_pointer_cast<pgp_data::packets::PublicKeyPacket>(*iter);
                if (!public_key_packet_ptr)
                {
                    return nullptr;
                }
                
                KeyIDData current_id = public_key_packet_ptr->GetKeyID();
                if (key_id.size() == current_id.size())
                {
                    if (std::equal(key_id.begin(), key_id.end(), current_id.begin()))
                    {
                        return public_key_packet_ptr;
                    }
                }
            }
            
            if (((*iter)->GetPacketType() == PT_SECRET_KEY_PACKET) || ((*iter)->GetPacketType() == PT_SECRET_SUBKEY_PACKET))
            {
                crypto::SecretKeyPacketPtr secret_key_packet_ptr = std::dynamic_pointer_cast<pgp_data::packets::SecretKeyPacket>(*iter);
                if (!secret_key_packet_ptr)
                {
                    return nullptr;
                }
                
                KeyIDData current_id = secret_key_packet_ptr->GetKeyID();
                if (key_id.size() == current_id.size())
                {
                    if (std::equal(key_id.begin(), key_id.end(), current_id.begin()))
                    {
                        return secret_key_packet_ptr->GetPublicKeyPatr();
                    }
                }
            }

        }
        
        return nullptr;
    }
    
    /// NOTE!!! method dublicated in KeyGenerator.cpp
    bool GetDataForKeySignature(crypto::SignaturePacketPtr signature_packet, crypto::PublicKeyPacketPtr signed_public_key_packet, pgp_data::packets::UserIDPacketPtr signed_user_id_packet, CharDataVector& data)
    {
        CharDataVector data_for_sign;
        
        CharDataVector key_data;
        signed_public_key_packet->GetRawData(key_data);
        
        data_for_sign.push_back(0x99);
        
        data_for_sign.push_back((key_data.size() >> 8) & 0xff);
        data_for_sign.push_back(key_data.size() & 0xff);
        
        data_for_sign.insert(data_for_sign.end(), key_data.begin(), key_data.end());
        
        CharDataVector user_id_data;
        signed_user_id_packet->GetRawData(user_id_data);
        if (signature_packet->GetPacketVersion() == 3)
        {
            data_for_sign.insert(data_for_sign.end(), user_id_data.begin(), user_id_data.end());
        }
        else if (signature_packet->GetPacketVersion() == 4)
        {
            data_for_sign.push_back(0xb4);
            
            data_for_sign.push_back((user_id_data.size() >> 24) & 0xff);
            data_for_sign.push_back((user_id_data.size() >> 16) & 0xff);
            data_for_sign.push_back((user_id_data.size() >> 8) & 0xff);
            data_for_sign.push_back(user_id_data.size() & 0xff);
            
            data_for_sign.insert(data_for_sign.end(), user_id_data.begin(), user_id_data.end());
        }
        else
        {
            return false;
        }
        
        CharDataVector signature_packet_data;
        signature_packet->GetDataForHash(signature_packet_data);
        
        if (signature_packet->GetPacketVersion() == 3)
        {
            data_for_sign.insert(data_for_sign.end(), signature_packet_data.begin(), signature_packet_data.end());
            
        }
        else if (signature_packet->GetPacketVersion() == 4)
        {
            data_for_sign.insert(data_for_sign.end(), signature_packet_data.begin(), signature_packet_data.end());
            
            data_for_sign.push_back(0x04);
            data_for_sign.push_back(0xff);
            
            size_t signature_packet_data_size = signature_packet_data.size();
            
            data_for_sign.push_back((signature_packet_data_size >> 24) & 0xff);
            data_for_sign.push_back((signature_packet_data_size >> 16) & 0xff);
            data_for_sign.push_back((signature_packet_data_size >> 8) & 0xff);
            data_for_sign.push_back(signature_packet_data_size & 0xff);
        }
        else
        {
            return false;
        }
        
        data.assign(data_for_sign.begin(), data_for_sign.end());
        return true;
    }
    
    bool GetDataForKeySignature(crypto::SignaturePacketPtr signature_packet, crypto::PublicKeyPacketPtr public_key_packet, crypto::PublicKeyPacketPtr public_subkey_packet, CharDataVector& data)
    {
        CharDataVector data_for_sign;
        
        CharDataVector key_data;
        public_key_packet->GetRawData(key_data);
        
        data_for_sign.push_back(0x99);
        data_for_sign.push_back((key_data.size() >> 8) & 0xff);
        data_for_sign.push_back(key_data.size() & 0xff);
        
        data_for_sign.insert(data_for_sign.end(), key_data.begin(), key_data.end());
        
        
        CharDataVector subkey_data;
        public_subkey_packet->GetRawData(subkey_data);
        
        data_for_sign.push_back(0x99);
        data_for_sign.push_back((subkey_data.size() >> 8) & 0xff);
        data_for_sign.push_back(subkey_data.size() & 0xff);
        
        data_for_sign.insert(data_for_sign.end(), subkey_data.begin(), subkey_data.end());
        
        
        CharDataVector signature_packet_data;
        signature_packet->GetDataForHash(signature_packet_data);
         
        if (signature_packet->GetPacketVersion() == 3)
        {
            data_for_sign.insert(data_for_sign.end(), signature_packet_data.begin(), signature_packet_data.end());
        }
        else if (signature_packet->GetPacketVersion() == 4)
        {
            data_for_sign.insert(data_for_sign.end(), signature_packet_data.begin(), signature_packet_data.end());
         
            data_for_sign.push_back(0x04);
            data_for_sign.push_back(0xff);
         
            unsigned int signature_packet_data_size = static_cast<int>(signature_packet_data.size());
         
            data_for_sign.push_back((signature_packet_data_size >> 24) & 0xff);
            data_for_sign.push_back((signature_packet_data_size >> 16) & 0xff);
            data_for_sign.push_back((signature_packet_data_size >> 8) & 0xff);
            data_for_sign.push_back(signature_packet_data_size & 0xff);
        }
        else
        {
            return false;
        }
        
        data.assign(data_for_sign.begin(), data_for_sign.end());
        return true;
    }
    
    bool CheckKeySignature(const PGPPacketsArray& packets)
    {
        std::vector<unsigned int> verified_keys;
        
        auto start_search_iter = packets.begin();
        
        crypto::PublicKeyPacketPtr signed_public_key_packet;
        pgp_data::packets::UserIDPacketPtr signed_user_id_packet;
        
        for (auto iter = packets.begin(); iter != packets.end(); ++iter)
        {
            if ((*iter)->GetPacketType() == PT_SIGNATURE_PACKET)
            {
                for (auto it = start_search_iter; it != iter; ++it)
                {
                    if ((*it)->GetPacketType() == PT_USER_ID_PACKET)
                    {
                        signed_user_id_packet = std::dynamic_pointer_cast<pgp_data::packets::UserIDPacket>(*it);
                    }
                    
                    if (((*it)->GetPacketType() == PT_PUBLIC_KEY_PACKET) || ((*it)->GetPacketType() == PT_PUBLIC_SUBKEY_PACKET))
                    {
                        signed_public_key_packet = std::dynamic_pointer_cast<pgp_data::packets::PublicKeyPacket>(*it);
                    }
                    
                    if (((*it)->GetPacketType() == PT_SECRET_KEY_PACKET) || ((*it)->GetPacketType() == PT_SECRET_SUBKEY_PACKET))
                    {
                        signed_public_key_packet = (std::dynamic_pointer_cast<pgp_data::packets::SecretKeyPacket>(*it))->GetPublicKeyPatr();
                    }
                }
                
                if ((!signed_user_id_packet) || (!signed_public_key_packet))
                {
                    return false;
                }
                
                crypto::SignaturePacketPtr signature_packet = std::dynamic_pointer_cast<pgp_data::packets::SignaturePacket>(*iter);
                
                crypto::PublicKeyPacketPtr public_key_packet = GetPublicKeyByID(packets, signature_packet->GetKeyID());
                if (!public_key_packet)
                {
                    return false;
                }

                CharDataVector data_for_sign;
                if (signature_packet->GetSignatureType() == 16)
                {
                    if (!GetDataForKeySignature(signature_packet, signed_public_key_packet, signed_user_id_packet, data_for_sign))
                    {
                        return false;
                    }
                }
                else if (signature_packet->GetSignatureType() == 24)
                {
                }
                
                //calculate current digest
                CharDataVector current_dash;
                CharDataVector digest_start;
                crypto::CalculateDigest(data_for_sign, signature_packet, current_dash, digest_start);
                
                //decrypt digest
                CharDataVector decoded_digest_data(current_dash);
                crypto::GetDigestData(signature_packet, public_key_packet, decoded_digest_data);
                if(decoded_digest_data.empty())
                {
                    return false;
                }
                
                if (current_dash.size() == decoded_digest_data.size())
                {
                    if (std::equal(current_dash.begin(), current_dash.end(), decoded_digest_data.begin()))
                    {
                        verified_keys.push_back(public_key_packet->GetKeyID()[1]);
                    }
                }
            }
            
            if ((iter + 1) == packets.end())
            {
                return false;
            }
            start_search_iter = iter++;
        }

        return false;
    }
}

namespace cryptopglib::pgp_parser {

    PGPParser::PGPParser() {

    }

    PGPMessagePtr PGPParser::ParseMessage(const std::string &source) {
        PGPMessageParser message_parser;
        PGPMessagePtr message_ptr = message_parser.ParseMessage(source);

        if (message_ptr) {
            PGPPacketsParser packet_parser(message_ptr->GetRawData());
            PGPPacketsArray packets = packet_parser.ParsePackets();
            if (packets.empty()) {
                return nullptr;
            }
            message_ptr->SetPackets(packets);

            if ((message_ptr->GetMessageType() == PGPMessageType::kPublicKey)
                || (message_ptr->GetMessageType() == PGPMessageType::kPrivateKey)) {
                if (IsKeySigned(packets)) {
                    CheckKeySignature(packets);
                }
            }
        }

        return message_ptr;
    }
}
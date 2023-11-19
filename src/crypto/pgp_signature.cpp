//
//  PGPSignature.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 14.6.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "pgp_signature.h"

#include "pgpg_decrypt.h"
#include "public_key_algorithms_impl.h"
#include "../pgp_parser/pgp_parser.h"
#include "../pgp_message_impl.h"
#include "../pgp_data/packets/public_key_packet.h"
#include "../pgp_data/packets/secret_key_packet.h"
#include "../pgp_data/packets/user_id_packet.h"

#include <algorithm>

#include <time.h>


namespace
{
    size_t GetMPIDataLength(cryptopglib::DataBuffer& data_buffer)
    {
        int l = data_buffer.GetNextTwoOctets();
        l = (l + 7) / 8;
        
        return l;
    }
        
    void ReplaceEndLine(std::string& str)
    {
        if (str.empty())
        {
            return;
        }
        
        size_t current_pos = 0;
        size_t find_pos = std::string::npos;
        do
        {
            find_pos = str.find('\n', current_pos);
            if (find_pos != std::string::npos)
            {
                if (find_pos == 0)
                {
                    str.replace(find_pos, 1, "\r\n");
                    current_pos = find_pos + 2;
                }
                else if (str[find_pos - 1] != '\r')
                {
                    str.replace(find_pos, 1, "\r\n");
                    current_pos = find_pos + 2;
                }
                else
                {
                    current_pos = find_pos + 1;
                }
                
            }
        }
        while(find_pos != std::string::npos);
        
        if (str[str.length() - 1] == '\r')
        {
            str.erase(str.end() - 1);
        }
    }
    
    bool CalculateSignature(cryptopglib::PGPMessagePtr message, cryptopglib::CharDataVector& hash)
    {
        const cryptopglib::PGPPacketsArray& message_packets = message->GetPackets();
        
        std::string plain_text = message->GetPlainText();
        ReplaceEndLine(plain_text);
        cryptopglib::CharDataVector data(plain_text.begin(), plain_text.end());
        
        cryptopglib::crypto::SignaturePacketPtr sig_packet = std::dynamic_pointer_cast<cryptopglib::pgp_data::packets::SignaturePacket>(message_packets[0]);
        if (sig_packet->GetPacketVersion() < 4)
        {
        
            data.push_back(sig_packet->GetSignatureType());
            unsigned int creation_time = sig_packet->GetCreationTime();
            
            data.push_back((creation_time >> 24) & 0xFF);
            data.push_back((creation_time >> 16) & 0xFF);
            data.push_back((creation_time >> 8) & 0xFF);
            data.push_back(creation_time & 0xFF);
        }
        else
        {

            cryptopglib::CharDataVector signature_packet_hashed_data;
            sig_packet->GetDataForHash(signature_packet_hashed_data);
            
            data.insert(data.end(), signature_packet_hashed_data.begin(), signature_packet_hashed_data.end());
            data.push_back(0x04);
            data.push_back(0xff);
            
            unsigned int size = signature_packet_hashed_data.size();
            data.push_back((size >> 24) & 0xFF);
            data.push_back((size >> 16) & 0xFF);
            data.push_back((size >> 8) & 0xFF);
            data.push_back(size & 0xFF);
        }
        
        cryptopglib::crypto::HashAlgorithmPtr hash_impl(cryptopglib::crypto::GetHashImpl(sig_packet->GetHashAlgorithm()));
        if (!hash_impl)
        {
            return false;
        }
        
        if (!hash_impl->Hash(data, hash))
        {
            return false;
        }
        
        std::vector<int> digest_start = {hash[0], hash[1]};
        sig_packet->SetDigestStart(digest_start);

        if (sig_packet->GetPublicKeyAlgorithm() != cryptopglib::PKA_DSA)
        {
            hash.insert(hash.begin(), hash_impl->GetHashPrefix().begin(), hash_impl->GetHashPrefix().end());
        }
        
        return true;
    }
    
    bool CalculateSignature(const cryptopglib::CharDataVector& data, cryptopglib::crypto::SignaturePacketPtr signature_packet_ptr, cryptopglib::CharDataVector& hash)
    {
        cryptopglib::CharDataVector temp_data(data);

        if (signature_packet_ptr->GetPacketVersion() < 4)
        {
            
            temp_data.push_back(signature_packet_ptr->GetSignatureType());
            unsigned int creation_time = signature_packet_ptr->GetCreationTime();
            
            temp_data.push_back((creation_time >> 24) & 0xFF);
            temp_data.push_back((creation_time >> 16) & 0xFF);
            temp_data.push_back((creation_time >> 8) & 0xFF);
            temp_data.push_back(creation_time & 0xFF);
        }
        else
        {
            
            cryptopglib::CharDataVector signature_packet_hashed_data;
            signature_packet_ptr->GetDataForHash(signature_packet_hashed_data);
            
            temp_data.insert(temp_data.end(), signature_packet_hashed_data.begin(), signature_packet_hashed_data.end());
            temp_data.push_back(0x04);
            temp_data.push_back(0xff);
            
            unsigned int size = signature_packet_hashed_data.size();
            temp_data.push_back((size >> 24) & 0xFF);
            temp_data.push_back((size >> 16) & 0xFF);
            temp_data.push_back((size >> 8) & 0xFF);
            temp_data.push_back(size & 0xFF);
        }
        
        cryptopglib::crypto::HashAlgorithmPtr hash_impl = cryptopglib::crypto::GetHashImpl(signature_packet_ptr->GetHashAlgorithm());
        if (!hash_impl)
        {
            std::cout << "hash algorithm not exist" << std::endl;
            return false;
        }
        
        if (!hash_impl->Hash(temp_data, hash))
        {
            std::cout << "hash algorithm error" << std::endl;
            return false;
        }
        
        std::vector<int> digest_start = {hash[0], hash[1]};
        signature_packet_ptr->SetDigestStart(digest_start);

        if (signature_packet_ptr->GetPublicKeyAlgorithm() != cryptopglib::PKA_DSA)
        {
            hash.insert(hash.begin(), hash_impl->GetHashPrefix().begin(), hash_impl->GetHashPrefix().end());
        }
        
        return true;
    }
    
    cryptopglib::crypto::PublicKeyPacketPtr GetKeyPacket(cryptopglib::PGPMessagePtr pub_key_ptr, const cryptopglib::KeyIDData& key_id)
    {
        const cryptopglib::PGPPacketsArray& pub_key_packets = pub_key_ptr->GetPackets();
        
        for (auto iter = pub_key_packets.begin(); iter != pub_key_packets.end(); ++iter)
        {
            if (((*iter)->GetPacketType() == cryptopglib::PT_PUBLIC_KEY_PACKET) || ((*iter)->GetPacketType() == cryptopglib::PT_PUBLIC_SUBKEY_PACKET))
            {
                cryptopglib::crypto::PublicKeyPacketPtr key_packet = std::dynamic_pointer_cast<cryptopglib::pgp_data::packets::PublicKeyPacket>(*iter);
                cryptopglib::KeyIDData sig_id = key_packet->GetKeyID();
                
                if (key_id.size() == sig_id.size())
                {
                    if (std::equal(key_id.begin(), key_id.end(), sig_id.begin()))
                    {
                        return key_packet;
                    }
                }
            }

            if (((*iter)->GetPacketType() == cryptopglib::PT_SECRET_KEY_PACKET) || ((*iter)->GetPacketType() == cryptopglib::PT_SECRET_SUBKEY_PACKET))
            {
                cryptopglib::crypto::SecretKeyPacketPtr key_packet = std::dynamic_pointer_cast<cryptopglib::pgp_data::packets::SecretKeyPacket>(*iter);
                cryptopglib::KeyIDData sig_id = key_packet->GetKeyID();
                
                if (key_id.size() == sig_id.size())
                {
                    if (std::equal(key_id.begin(), key_id.end(), sig_id.begin()))
                    {
                        return key_packet->GetPublicKeyPatr();
                    }
                }
            }
        }
        
        return nullptr;
    }
    
    bool DecodeSignature(cryptopglib::crypto::SignaturePacketPtr sig_packet, cryptopglib::PGPMessagePtr pub_key_ptr, cryptopglib::CharDataVector& hash, cryptopglib::CharDataVector& current_hash)
    {
        cryptopglib::KeyIDData sig_id = sig_packet->GetKeyID();
        cryptopglib::crypto::PublicKeyPacketPtr pub_key_packet = GetKeyPacket(pub_key_ptr, sig_id);
        if (pub_key_packet == nullptr)
        {
            //TODO: handle error
            return false;
        }
    
        cryptopglib::PublicKeyAlgorithms algo = sig_packet->GetPublicKeyAlgorithm();
        
        std::shared_ptr<cryptopglib::crypto::HashAlgorithm> hash_impl(cryptopglib::crypto::GetHashImpl(sig_packet->GetHashAlgorithm()));
        if (!hash_impl)
        {
            //TODO: handle error
            return false;
        }	
        
        hash.resize(hash_impl->GetDigestLength() + hash_impl->GetHashPrefix().size());
        
        cryptopglib::crypto::PublicKeyAlgorithmPtr public_key_algo_impl = cryptopglib::crypto::GetPublicKeyAlgorithm(algo);
        cryptopglib::CharDataVector crypted_signature = (sig_packet->GetMPI(0));
        if (algo == cryptopglib::PKA_DSA)
        {
            bool correct = public_key_algo_impl->DecryptWithPublicKey(pub_key_packet, current_hash, crypted_signature);
            if (correct)
            {
                hash.assign(current_hash.begin(), current_hash.end());
            }
        }
        else
        {
            public_key_algo_impl->DecryptWithPublicKey(pub_key_packet, crypted_signature, hash);
        }
        
        if (sig_packet->GetDigestStart().size() == 2)
        {
            if (algo == cryptopglib::PKA_DSA)
            {
               if ((sig_packet->GetDigestStart()[0] != hash[0]) ||
                    (sig_packet->GetDigestStart()[1] != hash[1]))
                {
                    // TODO: set error reason
                    return false;
                }
                
            }
            else
            {
                if ((sig_packet->GetDigestStart()[0] != hash[hash_impl->GetHashPrefix().size()]) ||
                    (sig_packet->GetDigestStart()[1] != hash[hash_impl->GetHashPrefix().size() + 1]))
                {
                    // TODO: set error reason
                    return false;
                }
            }
        }

        return true;
    }
    
    
    bool CryptSignature(const cryptopglib::CharDataVector& current_hash, cryptopglib::crypto::SecretKeyPacketPtr secret_key, cryptopglib::CharDataVector& enctypt_hash)
    {
        cryptopglib::PublicKeyAlgorithms pub_key_algo = secret_key->GetPublicKeyPatr()->GetPublicKeyAlgorithm();
        cryptopglib::crypto::PublicKeyAlgorithmPtr public_key_algo_impl = cryptopglib::crypto::GetPublicKeyAlgorithm(pub_key_algo);
        
        int len = public_key_algo_impl->EncryptWithPrivateKey(secret_key, current_hash, enctypt_hash);
        if (len <= 0)
        {
            return  false;
        }
        
        return  true;
    }
    
    bool HashData(cryptopglib::HashAlgorithms hash_algo, const cryptopglib::CharDataVector& data, cryptopglib::CharDataVector& session_key)
    {
        std::shared_ptr<cryptopglib::crypto::HashAlgorithm> hash_impl(cryptopglib::crypto::GetHashImpl(hash_algo));
        if (!hash_impl)
        {
            return false;
        }

        if (hash_impl->Hash(data, session_key))
        {
            return  true;
        }
        
        return false;
    }
    

    cryptopglib::crypto::SecretKeyPacketPtr GetPrivateKeyForSignature(const cryptopglib::PGPPacketsArray& packets)
    {
        return std::dynamic_pointer_cast<cryptopglib::pgp_data::packets::SecretKeyPacket>(packets[0]);
    }
    
    cryptopglib::crypto::PublicKeyPacketPtr GetPublicKeyByID(const cryptopglib::PGPPacketsArray& packets, const cryptopglib::KeyIDData& key_id)
    {
        for (auto iter = packets.begin(); iter != packets.end(); ++iter)
        {
            if (((*iter)->GetPacketType() == cryptopglib::PT_PUBLIC_KEY_PACKET) || ((*iter)->GetPacketType() == cryptopglib::PT_PUBLIC_SUBKEY_PACKET))
            {
                cryptopglib::crypto::PublicKeyPacketPtr public_key_packet_ptr = std::dynamic_pointer_cast<cryptopglib::pgp_data::packets::PublicKeyPacket>(*iter);
                if (!public_key_packet_ptr)
                {
                    return nullptr;
                }
                
                cryptopglib::KeyIDData current_id = public_key_packet_ptr->GetKeyID();
                if (key_id.size() == current_id.size())
                {
                    if (std::equal(key_id.begin(), key_id.end(), current_id.begin()))
                    {
                        return public_key_packet_ptr;
                    }
                }
            }
            
            if (((*iter)->GetPacketType() == cryptopglib::PT_SECRET_KEY_PACKET) || ((*iter)->GetPacketType() == cryptopglib::PT_SECRET_SUBKEY_PACKET))
            {
                cryptopglib::crypto::SecretKeyPacketPtr secret_key_packet_ptr = std::dynamic_pointer_cast<cryptopglib::pgp_data::packets::SecretKeyPacket>(*iter);
                if (!secret_key_packet_ptr)
                {
                    return nullptr;
                }
                
                cryptopglib::KeyIDData current_id = secret_key_packet_ptr->GetKeyID();
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
    
    bool GetDataForKeySignature(cryptopglib::crypto::SignaturePacketPtr signature_packet, cryptopglib::crypto::PublicKeyPacketPtr signed_public_key_packet, cryptopglib::pgp_data::packets::UserIDPacketPtr signed_user_id_packet, cryptopglib::CharDataVector& data)
    {
        cryptopglib::CharDataVector data_for_sign;
        
        cryptopglib::CharDataVector key_data;
        signed_public_key_packet->GetRawData(key_data);
        
        data_for_sign.push_back(0x99);
        
        data_for_sign.push_back((key_data.size() >> 8) & 0xff);
        data_for_sign.push_back(key_data.size() & 0xff);
        
        data_for_sign.insert(data_for_sign.end(), key_data.begin(), key_data.end());
        
        cryptopglib::CharDataVector user_id_data;
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
        
        cryptopglib::CharDataVector signature_packet_data;
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
}

namespace cryptopglib::crypto
{
    using namespace  pgp_data::packets;
    SignatureKeyInfo GetSignatureKeyID(PGPMessagePtr message_ptr)
    {
        // TODO : check if it correct work always
        SignatureKeyInfo signature_key_info;
        std::shared_ptr<PGPPacket> packet = message_ptr->GetPackets()[0];
        if (packet->GetPacketType() == PT_SIGNATURE_PACKET)
        {
            signature_key_info.keyID = (dynamic_cast<SignaturePacket*>(packet.get()))->GetKeyID();
            signature_key_info.createdTime = (dynamic_cast<SignaturePacket*>(packet.get()))->GetCreationTime();
            signature_key_info.expirationTime = (dynamic_cast<SignaturePacket*>(packet.get()))->GetExpiredSignatureTime();
            
            return signature_key_info;
        }
        
        return SignatureKeyInfo();
    }
    
    SignatureResultInfo CheckSignature(PGPMessagePtr message_ptr, const std::string& public_key)
    {
        SignatureKeyInfo signature_key_info = (GetSignatureKeyID(message_ptr));
        KeyIDData key_id = signature_key_info.keyID;
        
        SignatureResultInfo signature_result;
        
        if (key_id.size() != 2)
        {
            // TODO: handle key error
            signature_result.signature_result_ = SR_NONE_SIGNATURE;
            return signature_result;
        }
        
        std::string public_key_data = public_key;
        pgp_parser::PGPParser parser;
        PGPMessagePtr pub_key_ptr = parser.ParseMessage(public_key_data);
        if (pub_key_ptr == nullptr)
        {
            signature_result.signature_result_ = SR_KEY_NOT_FOUND;
            return signature_result;
        }
        
        CharDataVector current_hash;
        if (!CalculateSignature(message_ptr, current_hash))
        {
            signature_result.signature_result_ = SR_SIGNATURE_FAILURE;
            return signature_result;
        }

        CharDataVector decoded_hash;
        PGPPacketsArray packets = message_ptr->GetPackets();
        SignaturePacketPtr signature_packet = nullptr;
        for (PGPPacketsArray::iterator iter = packets.begin(); iter != packets.end(); ++iter)
        {
            if ((*iter)->GetPacketType() == PT_SIGNATURE_PACKET)
            {
                signature_packet = std::dynamic_pointer_cast<SignaturePacket>((*iter));
            }
        }
        
        if (signature_packet == nullptr)
        {
            signature_result.signature_result_ = SR_NONE_SIGNATURE;
            return signature_result;
        }
        
        if (!DecodeSignature(signature_packet, pub_key_ptr, decoded_hash, current_hash))
        {
            signature_result.signature_result_ = SR_SIGNATURE_FAILURE;
            return signature_result;
        }
        
        if (current_hash.size() != decoded_hash.size())
        {
            signature_result.signature_result_ = SR_SIGNATURE_FAILURE;
            return signature_result;
        }
        
        bool correct = std::equal(decoded_hash.begin(), decoded_hash.end(), current_hash.begin());
        
        signature_result.signature_result_ = correct ? SR_SIGNATURE_VERIFIED : SR_SIGNATURE_FAILURE;
        signature_result.create_signature_time_ = signature_packet->GetCreationTime();
        signature_result.expired_signature_time_ = signature_packet->GetExpiredSignatureTime();
        
        return signature_result;
    }
    
    CheckSignatureResult CheckSignature(CharDataVector data, SignaturePacketPtr signature_packet, const std::string& public_key)
    {
        pgp_parser::PGPParser parser;
        PGPMessagePtr pub_key_ptr = parser.ParseMessage(public_key);
        if (pub_key_ptr == nullptr)
        {
            return SR_KEY_NOT_FOUND;
        }
        
        CharDataVector current_hash;
        if (!CalculateSignature(data, signature_packet, current_hash))
        {
            return SR_SIGNATURE_FAILURE;
        }
        
        CharDataVector decoded_hash;
        if (!DecodeSignature(signature_packet, pub_key_ptr, decoded_hash, current_hash))
        {
            return SR_SIGNATURE_FAILURE;
        }
        
        if (current_hash.size() != decoded_hash.size())
        {
            return SR_SIGNATURE_FAILURE;
        }
        
        bool correct = std::equal(decoded_hash.begin(), decoded_hash.end(), current_hash.begin());
        
        return correct ? SR_SIGNATURE_VERIFIED : SR_SIGNATURE_FAILURE;
    }
    
    CheckSignatureResult CheckKeySignature(const std::string& signed_key_data, const std::string& verification_key_data)
    {
        pgp_parser::PGPParser parser;
        PGPMessagePtr verification_key_ptr = parser.ParseMessage(verification_key_data);
        if (verification_key_ptr == nullptr)
        {
            return SR_KEY_NOT_FOUND;
        }
        
        PGPMessagePtr signed_key_ptr = parser.ParseMessage(signed_key_data);
        if (signed_key_ptr == nullptr)
        {
            return SR_NONE_SIGNATURE;
        }

        PublicKeyPacketPtr signed_public_key_packet;
        pgp_data::packets::UserIDPacketPtr signed_user_id_packet;
        
        PGPPacketsArray signed_key_packets = signed_key_ptr->GetPackets();
        PGPPacketsArray verification_key_packets = verification_key_ptr->GetPackets();
        
        auto start_search_iter = signed_key_packets.begin();
        for (auto iter = signed_key_packets.begin(); iter != signed_key_packets.end(); ++iter)
        {
            if ((*iter)->GetPacketType() == PT_SIGNATURE_PACKET)
            {
                for (auto it = start_search_iter; it != iter; ++it)
                {
                    if ((*it)->GetPacketType() == PT_USER_ID_PACKET)
                    {
                        signed_user_id_packet = std::dynamic_pointer_cast<UserIDPacket>(*it);
                    }
                    
                    if (((*it)->GetPacketType() == PT_PUBLIC_KEY_PACKET) || ((*it)->GetPacketType() == PT_PUBLIC_SUBKEY_PACKET))
                    {
                        signed_public_key_packet = std::dynamic_pointer_cast<PublicKeyPacket>(*it);
                    }
                    
                    if (((*it)->GetPacketType() == PT_SECRET_KEY_PACKET) || ((*it)->GetPacketType() == PT_SECRET_SUBKEY_PACKET))
                    {
                        signed_public_key_packet = (std::dynamic_pointer_cast<SecretKeyPacket>(*it))->GetPublicKeyPatr();
                    }
                }
                
                if ((!signed_user_id_packet) || (!signed_public_key_packet))
                {
                    return SR_NONE_SIGNATURE;
                }
                
                SignaturePacketPtr signature_packet = std::dynamic_pointer_cast<SignaturePacket>(*iter);
                
                PublicKeyPacketPtr public_key_packet = GetPublicKeyByID(verification_key_packets, signature_packet->GetKeyID());
                if (!public_key_packet)
                {
                    continue;
                }
                
                CharDataVector data_for_sign;
                if (signature_packet->GetSignatureType() == 16)
                {
                    if (!GetDataForKeySignature(signature_packet, signed_public_key_packet, signed_user_id_packet, data_for_sign))
                    {
                        return SR_SIGNATURE_FAILURE;
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
                    return SR_SIGNATURE_FAILURE;
                }
                
                if (current_dash.size() == decoded_digest_data.size())
                {
                    if (std::equal(current_dash.begin(), current_dash.end(), decoded_digest_data.begin()))
                    {
                        return SR_SIGNATURE_VERIFIED;
                    }
                }
            }
            
            if ((iter + 1) == signed_key_packets.end())
            {
                return SR_NONE_SIGNATURE;
            }
            
            start_search_iter = iter++;
        }
        
        return SR_SIGNATURE_FAILURE;
    }
    
    PGPMessagePtr SignMessage(const std::string& message,
                              PGPMessagePtr private_key,
                              HashAlgorithms hash_algo)
    {
        SecretKeyPacketPtr secret_key = GetPrivateKeyForSignature(private_key->GetPackets());
        if (!secret_key)
        {
            return nullptr;
        }
        
        PGPMessagePtr sign_message(new PGPMessageImpl);
        sign_message->SetMessageType(PGPMessageType::kSignedMessage);
        sign_message->SetPlainText(message);
        
        SignaturePacketPtr packet(new SignaturePacket(3));
        packet->SetSignatureType(1);
        packet->SetPublicKeyAlgorithm(secret_key->GetPublicKeyPatr()->GetPublicKeyAlgorithm());
        packet->SetHashAlgorithm(hash_algo);

        packet->SetCreationTime(static_cast<unsigned int>(time(NULL)));
        
        KeyIDData key_id = secret_key->GetKeyID();
        packet->SetKeyID(key_id);
        
        sign_message->AddPacket(packet);
        CharDataVector current_hash;
        if (!CalculateSignature(sign_message, current_hash))
        {
            return nullptr;
        }
                
        CharDataVector encrypt_hash;
        CryptSignature(current_hash, secret_key, encrypt_hash);
        
        packet->AddMPI(encrypt_hash);
        
        return sign_message;
    }
    
    SignaturePacketPtr SignRawData(const CharDataVector& data, SecretKeyPacketPtr secret_key, HashAlgorithms hash_algo)
    {
        SignaturePacketPtr signature_packet_ptr(new SignaturePacket(3));
        signature_packet_ptr->SetSignatureType(1);
        signature_packet_ptr->SetPublicKeyAlgorithm(secret_key->GetPublicKeyPatr()->GetPublicKeyAlgorithm());
        signature_packet_ptr->SetHashAlgorithm(hash_algo);
        signature_packet_ptr->SetCreationTime(static_cast<unsigned int>(time(NULL)));

        KeyIDData key_id = secret_key->GetKeyID();
        signature_packet_ptr->SetKeyID(key_id);

        // calculate signature
        CharDataVector current_hash;
        if (!CalculateSignature(data, signature_packet_ptr, current_hash))
        {
            return nullptr;
        }
        
        CharDataVector encrypt_hash;
        CryptSignature(current_hash, secret_key, encrypt_hash);
        
        signature_packet_ptr->AddMPI(encrypt_hash);

        return signature_packet_ptr;
    }
    
    void GetDigestData(SignaturePacketPtr signature_packet_ptr, PublicKeyPacketPtr public_key_packet_ptr, CharDataVector& digest_data)
    {
        PublicKeyAlgorithms algo = signature_packet_ptr->GetPublicKeyAlgorithm();
        
        std::shared_ptr<crypto::HashAlgorithm> hash_impl(crypto::GetHashImpl(signature_packet_ptr->GetHashAlgorithm()));
        if (!hash_impl)
        {
            //TODO: handle error
            return;
        }
        
        crypto::PublicKeyAlgorithmPtr public_key_algo_impl = crypto::GetPublicKeyAlgorithm(algo);
        CharDataVector crypted_signature = (signature_packet_ptr->GetMPI(0));
        if (algo == PKA_DSA)
        {
            bool correct = public_key_algo_impl->DecryptWithPublicKey(public_key_packet_ptr, digest_data, crypted_signature);
            if (!correct)
            {
                return;
                //digest_data.empty();
            }
        }
        else
        {
            digest_data.resize(hash_impl->GetDigestLength() + hash_impl->GetHashPrefix().size());
            public_key_algo_impl->DecryptWithPublicKey(public_key_packet_ptr, crypted_signature, digest_data);
        }
        
        if (digest_data.empty())
        {
            return;
        }
        
        if (signature_packet_ptr->GetDigestStart().size() == 2)
        {
            if (algo == PKA_DSA)
            {
                if ((signature_packet_ptr->GetDigestStart()[0] != digest_data[0]) ||
                    (signature_packet_ptr->GetDigestStart()[1] != digest_data[1]))
                {
                    // TODO: set error reason
                    digest_data.clear();
                    return;
                }
                
            }
            else
            {
                if ((signature_packet_ptr->GetDigestStart()[0] != digest_data[hash_impl->GetHashPrefix().size()]) ||
                    (signature_packet_ptr->GetDigestStart()[1] != digest_data[hash_impl->GetHashPrefix().size() + 1]))
                {
                    // TODO: set error reason
                    digest_data.clear();
                    return;
                }
            }
        }
    }
    
    bool CalculateDigest(const CharDataVector& data, SignaturePacketPtr signature_packet_ptr, CharDataVector& hash, CharDataVector& digest_start)
    {
        crypto::HashAlgorithmPtr hash_impl = crypto::GetHashImpl(signature_packet_ptr->GetHashAlgorithm());
        if (!hash_impl)
        {
            return false;
        }
        
        if (!hash_impl->Hash(data, hash))
        {
            return false;
        }
        
        if (signature_packet_ptr->GetPublicKeyAlgorithm() != PKA_DSA)
        {
            digest_start.clear();
            digest_start.push_back(hash[0]);
            digest_start.push_back(hash[1]);
            hash.insert(hash.begin(), hash_impl->GetHashPrefix().begin(), hash_impl->GetHashPrefix().end());
        }
        
        return true;
    }
    
    PGPMessagePtr SignPublicKey(PGPMessagePtr public_key, PGPMessagePtr private_key)
    {
        if ((private_key == nullptr) || (public_key == nullptr))
        {
            return nullptr;
        }
        
        SecretKeyPacketPtr secret_key = GetPrivateKeyForSignature(private_key->GetPackets());
        if (!secret_key)
        {
            return nullptr;
        }
        
        PublicKeyPacketPtr signed_public_key_packet;
        UserIDPacketPtr signed_user_id_packet;
        PGPPacketsArray signed_key_packets = public_key->GetPackets();
        auto insert_iterator = signed_key_packets.begin();
        for (auto iter = signed_key_packets.begin(); iter != signed_key_packets.end(); ++iter)
        {
            if ((*iter)->GetPacketType() == PT_USER_ID_PACKET)
            {
                signed_user_id_packet = std::dynamic_pointer_cast<UserIDPacket>(*iter);
            }
            
            if ((*iter)->GetPacketType() == PT_PUBLIC_KEY_PACKET)
            {
                signed_public_key_packet = std::dynamic_pointer_cast<PublicKeyPacket>(*iter);
            }
            
            if ((*iter)->GetPacketType() == PT_SIGNATURE_PACKET)
            {
                insert_iterator = iter;
                break;
            }
        }
        
        if ((signed_public_key_packet == nullptr) || (signed_user_id_packet == nullptr))
        {
            return nullptr;
        }
        
        HashAlgorithms hash_algo = HashAlgorithms::HA_SHA256;
        
        SignaturePacketPtr signature_packet_ptr(new SignaturePacket(3));
        signature_packet_ptr->SetSignatureType(25);
        signature_packet_ptr->SetPublicKeyAlgorithm(secret_key->GetPublicKeyPatr()->GetPublicKeyAlgorithm());
        signature_packet_ptr->SetHashAlgorithm(hash_algo);
        signature_packet_ptr->SetPublicKeyAlgorithm(PKA_RSA);
        signature_packet_ptr->SetCreationTime(static_cast<unsigned int>(time(NULL)));
        
        KeyIDData key_id = secret_key->GetKeyID();
        signature_packet_ptr->SetKeyID(key_id);
        
        CharDataVector data_for_sign;
        if (GetDataForKeySignature(signature_packet_ptr, signed_public_key_packet, signed_user_id_packet, data_for_sign))
        {
            CharDataVector hash;
            CharDataVector digest_start;
            if (crypto::CalculateDigest(data_for_sign, signature_packet_ptr, hash, digest_start))
            {
                std::vector<int> temp = {digest_start[0], digest_start[1]};
                signature_packet_ptr->SetDigestStart(temp);
                
                PublicKeyAlgorithmPtr pub_key_algo_impl = GetPublicKeyAlgorithm(signature_packet_ptr->GetPublicKeyAlgorithm());
                CharDataVector crypto_result;
                
                pub_key_algo_impl->EncryptWithPrivateKey(secret_key, hash, crypto_result);
                
                signature_packet_ptr->AddMPI(crypto_result);
            }

            signed_key_packets.insert(insert_iterator, signature_packet_ptr);
            
            return public_key;
        }
    
        return nullptr;
    }

}

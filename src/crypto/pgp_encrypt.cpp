//
//  PGPEncrypt.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 3.11.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "pgp_encrypt.h"

#include <numeric>

#include "key_generator.h"
#include "symmetric_key_algorithms.h"
#include "public_key_algorithms.h"
#include "public_key_algorithms_impl.h"
#include "../pgp_data/packets/marker_packet.h"
#include "../pgp_data/packets/secret_key_packet.h"
#include "../pgp_data/packets/public_key_encrypted_packet.h"
#include "../pgp_data/packets/symmetrically_encrypted_data_packet.h"
#include "../pgp_data/packets/literal_data_packet.h"
#include "../pgp_data/packets/compressed_data_packet.h"

#include "../pgp_parser/pgp_packets_parser.h"


namespace
{
    PGPPacketPtr GeneratePGPMarkerPacket()
    {
        MarkerPacketPtr marker_packet(new   MarkerPacket);
        CharDataVector pgp_marker_data  = {0x50, 0x47, 0x50};
        marker_packet->SetData(pgp_marker_data);
        
        return marker_packet;
    }
    
    void PrepareSessionKeyForEncrypt(CharDataVector& session_key, SymmetricKeyAlgorithms algo)
    {
        int checksum = std::accumulate(session_key.begin(), session_key.end(), 0);
        checksum = checksum % 65536;

        session_key.insert(session_key.begin(), algo);
        session_key.push_back((checksum >> 8) & 0xFF);
        session_key.push_back(checksum & 0xFF);
    }
    
    PublicKeyPacketPtr GetPublicKeyPacketForEncrypt(PGPMessagePtr key_message)
    {
        const PGPPacketsArray& public_key_packets = key_message->GetPackets();
        
        PublicKeyPacketPtr public_key_packet(nullptr);
        PGPMessageType message_type = key_message->GetMessageType();
        
        for (auto iter = public_key_packets.begin(); iter != public_key_packets.end(); ++iter)
        {
                if (((*iter)->GetPacketType() == PT_PUBLIC_KEY_PACKET) || ((*iter)->GetPacketType() == PT_PUBLIC_SUBKEY_PACKET)
                    || ((*iter)->GetPacketType() == PT_SECRET_KEY_PACKET) || ((*iter)->GetPacketType() == PT_SECRET_SUBKEY_PACKET))
                {
                    if (message_type == PGPMessageType::kPublicKey)
                    {
                        public_key_packet = std::dynamic_pointer_cast<PublicKeyPacket>(*iter);
                    }
                    else
                    {
                        public_key_packet = (std::dynamic_pointer_cast<SecretKeyPacket>(*iter))->GetPublicKeyPatr();
                    }

                }
        }
        
        return public_key_packet;
    }
    
    PublicKeyEncryptedPacketPtr EncryptData(const CharDataVector& source, PublicKeyPacketPtr public_key_packet, PublicKeyAlgorithms algo)
    {
        PublicKeyEncryptedPacketPtr public_key_encrypted_packet(new PublicKeyEncryptedPacket);

        public_key_encrypted_packet->SetPublicKeyAlgorithm(algo);
        
        KeyIDData key_id = public_key_packet->GetKeyID();
        public_key_encrypted_packet->SetKeyID(key_id);
        
        crypto::PublicKeyAlgorithmPtr public_key_algo_impl = crypto::GetPublicKeyAlgorithm(algo);
        if (!public_key_algo_impl)
        {
            return nullptr;
        }
        
        CharDataVector encrypted_data;
        public_key_algo_impl->EncryptWithPublicKey(public_key_packet, source, encrypted_data);
        
        if (encrypted_data.empty())
        {
            return nullptr;
        }
        
        public_key_encrypted_packet->AddMPI(encrypted_data);
        
        return public_key_encrypted_packet;
    }
    
    SymmetricallyEncryptedDataPacketPtr EncryptData(CharDataVector& source, const CharDataVector& session_key, SymmetricKeyAlgorithms algo)
    {
        SymmetricallyEncryptedDataPacketPtr symmetricaly_encrypted_data_packet(new SymmetricallyEncryptedDataPacket(PT_SYMMETRIC_ENCRYTPED_AND_INTEGRITY_PROTECTED_DATA_PACKET));
        
        crypto::SymmetricKeyAlgorithmPtr symmetric_key_algo_impl = crypto::GetSymmetricKeyAlgorithm(algo);
        CharDataVector initial_vector(symmetric_key_algo_impl->GetCipherBlockSize(), 0);
        
        CharDataVector random_data;
        crypto::GenerateSessionKey(symmetric_key_algo_impl->GetCipherBlockSize(), random_data, -1);
        if (random_data.size() != symmetric_key_algo_impl->GetCipherBlockSize())
        {
            return nullptr;
        }
        
        random_data.push_back(random_data[symmetric_key_algo_impl->GetCipherBlockSize() - 2]);
        random_data.push_back(random_data[symmetric_key_algo_impl->GetCipherBlockSize() - 1]);
        source.insert(source.begin(), random_data.begin(), random_data.end());
        
        source.push_back(0xd3);
        source.push_back(0x14);
        
        crypto::Sha1 sha1;
        CharDataVector dst;
        sha1.Hash(source, dst);
        
        source.insert(source.end(), dst.begin(), dst.end());
        
        CharDataVector ivec(symmetric_key_algo_impl->GetCipherBlockSize(), 0);
        CharDataVector encrypted_data;
        symmetric_key_algo_impl->EncryptInCFBMode(source, session_key, ivec, encrypted_data);
        ///
      if (encrypted_data.empty())
      {
        return nullptr;
      }
        symmetricaly_encrypted_data_packet->SetEncryptedData(encrypted_data);
        
        return symmetricaly_encrypted_data_packet;
    }
    
    CompressedDataPacketPtr CompressData(const CharDataVector& source, CompressionAlgorithms algo)
    {
        crypto::CompressionAlgorithmPtr compress_algo_impl =
                crypto::GetCompressionAlgorithmImpl(algo);
        
        if (compress_algo_impl == nullptr)
        {
            return nullptr;
        }
        CompressedDataPacketPtr compressed_data_packet(new CompressedDataPacket);
        compressed_data_packet->SetCompressAlgorithm(algo);
        
        CharDataVector compressed_data;
        compress_algo_impl->CompressData(source, compressed_data);
        
        compressed_data_packet->SetData(compressed_data);
        
        return compressed_data_packet;
    }
    
    PublicKeyAlgorithms GetPublicKeyAlgorithmFromKey(PGPMessagePtr key)
    {
        PGPPacketsArray packets = key->GetPackets();
        for (PGPPacketPtr packet_ptr : packets)
        {
            if ((packet_ptr->GetPacketType() == PT_PUBLIC_KEY_PACKET) || (packet_ptr->GetPacketType() == PT_PUBLIC_SUBKEY_PACKET))
            {
                PublicKeyPacketPtr public_key_packet = std::dynamic_pointer_cast<PublicKeyPacket>(packet_ptr);
                return public_key_packet->GetPublicKeyAlgorithm();
            }
            if ((packet_ptr->GetPacketType() == PT_SECRET_KEY_PACKET) || (packet_ptr->GetPacketType() == PT_SECRET_SUBKEY_PACKET))
            {
                SecretKeyPacketPtr secret_key_packet = std::dynamic_pointer_cast<SecretKeyPacket>(packet_ptr);
                return secret_key_packet->GetPublicKeyPatr()->GetPublicKeyAlgorithm();
            }
        }
        
        return PKA_RSA;
    }
}

namespace crypto
{
    PGPEncrypt::PGPEncrypt()
    {
    }
    
    PGPMessagePtr PGPEncrypt::EncryptMessage(const std::string& plain_text, std::vector<PGPMessagePtr>& addressers_pub_keys_ptr, PGPMessagePtr own_key_ptr, OpenPGPInfoGetterPtr pgp_info_getter_)
    {
        PGPMessagePtr encrypted_message(new PGPMessageImpl);
        encrypted_message->SetPlainText(plain_text);
        encrypted_message->SetMessageType(PGPMessageType::kEncryptedMessage);
        
        // -- Create PGPMarkerPacket --
        encrypted_message->AddPacket(GeneratePGPMarkerPacket());
        
        // -- Gnerate session key
        CharDataVector session_key;
        SymmetricKeyAlgorithms symmetric_key_algo = static_cast<SymmetricKeyAlgorithms>(pgp_info_getter_->GetSymmetricKeyAlgorithm());
        if (symmetric_key_algo != SKA_PLAIN_TEXT)
        {
            SymmetricKeyAlgorithmPtr symmetric_key_algo_impl = crypto::GetSymmetricKeyAlgorithm(symmetric_key_algo);
            if (!symmetric_key_algo_impl)
            {
                return nullptr;
            }
            
            GenerateSessionKey(symmetric_key_algo_impl->GetKeyLength(), session_key, pgp_info_getter_->GetSymmetricKeyAlgorithm());
            if (session_key.empty())
            {
                return nullptr;
            }
            
            //TODO delete this
            //
            /*for (int i = 0; i < session_key.size(); ++i)
            {
                session_key[i] = 0;
            }*/
            ///
            
            CharDataVector session_key_for_encrypt(session_key);
            PrepareSessionKeyForEncrypt(session_key_for_encrypt, symmetric_key_algo);
            
            for (PGPMessagePtr pub_key_ptr : addressers_pub_keys_ptr)
            {
                PublicKeyAlgorithms public_key_algo = GetPublicKeyAlgorithmFromKey(pub_key_ptr);
                if (PKA_DSA == public_key_algo)
                    public_key_algo = PKA_ELGAMAL;
                
                PublicKeyPacketPtr addresser_public_key_packet = GetPublicKeyPacketForEncrypt(pub_key_ptr);
                encrypted_message->AddPacket(EncryptData(session_key_for_encrypt, addresser_public_key_packet, public_key_algo));
            }
            
            PublicKeyAlgorithms public_key_algo = GetPublicKeyAlgorithmFromKey(own_key_ptr);
            PublicKeyPacketPtr own_public_key_packet = GetPublicKeyPacketForEncrypt(own_key_ptr);
            encrypted_message->AddPacket(EncryptData(session_key_for_encrypt, own_public_key_packet, public_key_algo));
        }
        
        LiteralDataPacket literal_data_packet;
        CharDataVector plain_text_data(plain_text.begin(), plain_text.end());
        literal_data_packet.SetData(plain_text_data);
        
        CompressionAlgorithms compress_algo = static_cast<CompressionAlgorithms>(pgp_info_getter_->GetCompressAlgorithm());
        if (compress_algo == CA_UNCOMPRESSED)
        {
            CharDataVector source_for_encrypt;
            literal_data_packet.GetBinaryData(source_for_encrypt);
            encrypted_message->AddPacket(EncryptData(source_for_encrypt, session_key, symmetric_key_algo));
        }
        else
        {
            CharDataVector source_for_compress;
            literal_data_packet.GetBinaryData(source_for_compress);
   
            CompressedDataPacketPtr compressed_data_packet = CompressData(source_for_compress, compress_algo);
            
            if (symmetric_key_algo != SKA_PLAIN_TEXT)
            {
                CharDataVector source_for_encrypt;
                compressed_data_packet->GetBinaryData(source_for_encrypt);
                encrypted_message->AddPacket(EncryptData(source_for_encrypt, session_key, symmetric_key_algo));
            }
            else
            {
                encrypted_message->AddPacket(compressed_data_packet);
            }
        }
        
        return encrypted_message;
    }
    
    PGPMessagePtr PGPEncrypt::EncryptRawData(const CharDataVector& data, std::vector<PGPMessagePtr>& addressers_pub_keys_ptr, PGPMessagePtr own_key_ptr, OpenPGPInfoGetterPtr pgp_info_getter_)
    {
        PGPMessagePtr encrypted_message(new PGPMessageImpl);
        // -- Create PGPMarkerPacket --
        encrypted_message->SetMessageType(PGPMessageType::kEncryptedMessage);
        encrypted_message->AddPacket(GeneratePGPMarkerPacket());
        
        // -- Gnerate session key
        CharDataVector session_key;
        SymmetricKeyAlgorithms symmetric_key_algo = static_cast<SymmetricKeyAlgorithms>(pgp_info_getter_->GetSymmetricKeyAlgorithm());
        if (symmetric_key_algo != SKA_PLAIN_TEXT)
        {
            SymmetricKeyAlgorithmPtr symmetric_key_algo_impl = crypto::GetSymmetricKeyAlgorithm(symmetric_key_algo);
            if (!symmetric_key_algo_impl)
            {
                return nullptr;
            }
            
            GenerateSessionKey(symmetric_key_algo_impl->GetKeyLength(), session_key, symmetric_key_algo);
            if (session_key.empty())
            {
                return nullptr;
            }
            
            CharDataVector session_key_for_encrypt(session_key);
            PrepareSessionKeyForEncrypt(session_key_for_encrypt, symmetric_key_algo);
            
            for (PGPMessagePtr pub_key_ptr : addressers_pub_keys_ptr)
            {
                                PublicKeyAlgorithms public_key_algo = GetPublicKeyAlgorithmFromKey(pub_key_ptr);
                PublicKeyPacketPtr addresser_public_key_packet = GetPublicKeyPacketForEncrypt(pub_key_ptr);
                encrypted_message->AddPacket(EncryptData(session_key_for_encrypt, addresser_public_key_packet, public_key_algo));
            }
            
            PublicKeyAlgorithms public_key_algo = GetPublicKeyAlgorithmFromKey(own_key_ptr);
            PublicKeyPacketPtr own_public_key_packet = GetPublicKeyPacketForEncrypt(own_key_ptr);
            encrypted_message->AddPacket(EncryptData(session_key_for_encrypt, own_public_key_packet, public_key_algo));
        }
        
        CharDataVector source_for_encrypt(data);
        encrypted_message->AddPacket(EncryptData(source_for_encrypt, session_key, symmetric_key_algo));
        
        return encrypted_message;
    }
    
}
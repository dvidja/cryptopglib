//
//  PGPDecrypt.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 4.8.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "PGPDecrypt.h"

#include "../utils/base64.h"

#include "../PGPMessageImpl.h"

#include "../PGPParser/PGPParser.h"
#include "../PGPParser/PGPPacketsParser.h"

#include "../IOpenPGPInfoGetter.h"

#include "SymmetricKeyAlgorithms.h"
#include "PGPSignature.h"
#include "PublicKeyAlgorithmsImpl.h"

#include <numeric>


namespace
{
    size_t GetMPIDataLength(DataBuffer& data_buffer)
    {
        int l = data_buffer.GetNextTwoOctets();
        l = (l + 7) / 8;
        
        return l;
    }
            
    bool IsDataDecryptedCorrect(const CharDataVector& data, const int block_size)
    {
        if (data.size() <= block_size + 2)
        {
            return false;
        }
        
        if ((data[block_size - 2] == data[block_size]) && (data[block_size - 1] == data[block_size + 1]))
        {
            return true;
        }
        
        return false;
    }
    
    SecretKeyPacketPtr GetKeyPacket(const KeyIDData& key_id, PGPMessagePtr sec_key_ptr)
    {
        const PGPPacketsArray& sec_key_packets = sec_key_ptr->GetPackets();
        
        for (auto iter = sec_key_packets.begin(); iter != sec_key_packets.end(); ++iter)
        {
            if (((*iter)->GetPacketType() == PT_SECRET_KEY_PACKET) || ((*iter)->GetPacketType() == PT_SECRET_SUBKEY_PACKET))
            {
                SecretKeyPacketPtr key_packet = std::dynamic_pointer_cast<SecretKeyPacket>((*iter));
                KeyIDData current_id = key_packet->GetKeyID();
                
                if (key_id.size() == current_id.size())
                {
                    if (std::equal(key_id.begin(), key_id.end(), current_id.begin()))
                    {
                        return key_packet;
                    }
                }
            }
        }
        
        return nullptr;
    }
    
    bool ExtractSeessionKeyData(PGPPacketsArray packets, PGPMessagePtr sec_key_ptr, const std::string& passphrase, CharDataVector& session_key_data)
    {
        for (auto iter = packets.begin(); iter != packets.end(); ++iter)
        {
            if ((*iter)->GetPacketType() == PT_PUBLIC_KEY_ENCRYPTED_PACKET)
            {
                PublicKeyEncryptedPacketPtr pub_key_enc = std::dynamic_pointer_cast<PublicKeyEncryptedPacket>((*iter));
                KeyIDData key_id = pub_key_enc->GetKeyID();
                
                SecretKeyPacketPtr sec_key = GetKeyPacket(key_id, sec_key_ptr);
                if (sec_key == nullptr)
                {
                    continue;
                }
                
                if (crypto::DecryptSessionKey(pub_key_enc, sec_key, session_key_data, passphrase))
                {
                    if (session_key_data.size() > 0)
                    {
                        return true;
                    }
                }
                
                session_key_data.clear();
            }
        }
        
        return false;
    }
}


namespace crypto
{
    bool DecryptSessionKey(PublicKeyEncryptedPacketPtr pub_key_enc, SecretKeyPacketPtr secret_key, CharDataVector& decrypt_data, const std::string& passphrase)
    {
        PublicKeyAlgorithms algo = pub_key_enc->GetPublicKeyAlgorithm();
        
        if (secret_key->GetSymmetricKeyAlgorithm() != SKA_PLAIN_TEXT)
        {
            if (passphrase.empty())
            {
                return false;
            }
            
            // !!! Test mode
            /*if (!DecryptSecretKeyData(secret_key, passphrase))
            {
                return false;
            }*/
        }
        
        //if ((algo == PKA_RSA) || (algo == PKA_RSA_ENCRYPT_ONLY) || (algo == PKA_RSA_SIGN_ONLY))
        {
            PublicKeyAlgorithmPtr public_key_algo_impl = GetPublicKeyAlgorithm(algo);
            if (!public_key_algo_impl)
            {
                return nullptr;
            }
            
            int len = public_key_algo_impl->DecryptWithPrivateKey(secret_key, pub_key_enc->GetMPI(0), decrypt_data);
            if (len <= 0)
            {
                return  false;
            }
            
            int checksum = decrypt_data[len - 2] << 8;
            checksum |= decrypt_data[len - 1];
            
            int testsum = std::accumulate(decrypt_data.begin() + 1, decrypt_data.begin() + len - 2, 0);
            testsum = testsum % 65536;
            
            if (checksum != testsum)
            {
                return false;
            }
        }
        
        return true;
    }

    PGPDecrypt::PGPDecrypt(IOpenPGPInfoGetterPtr pgp_info_getter)
        : pgp_info_getter_(pgp_info_getter)
    {
    }
    
    void PGPDecrypt::GetSecretKeyID(PGPMessagePtr crypt_msg, std::vector<KeyIDData>& key_ids)
    {
        PGPPacketsArray packets = crypt_msg->GetPackets();
        CharDataVector session_key_data;
        
        for (auto iter = packets.begin(); iter != packets.end(); ++iter)
        {
            if ((*iter)->GetPacketType() == PT_PUBLIC_KEY_ENCRYPTED_PACKET)
            {
                PublicKeyEncryptedPacketPtr pub_key_enc = std::dynamic_pointer_cast<PublicKeyEncryptedPacket>((*iter));
                KeyIDData temp_key_id = pub_key_enc->GetKeyID();
                
                key_ids.push_back(KeyIDData(temp_key_id.begin(), temp_key_id.end()));
            }
        }
    }
    
    bool PGPDecrypt::IsSecretKeyEncoded(PGPMessagePtr sec_key_ptr)
    {
        const PGPPacketsArray& sec_key_packets = sec_key_ptr->GetPackets();
        for (auto iter = sec_key_packets.begin(); iter != sec_key_packets.end(); ++iter)
        {
            if (((*iter)->GetPacketType() == PT_SECRET_KEY_PACKET) || ((*iter)->GetPacketType() == PT_SECRET_SUBKEY_PACKET))
            {
                SecretKeyPacketPtr key_packet = std::dynamic_pointer_cast<SecretKeyPacket>((*iter));
                if (key_packet->GetSymmetricKeyAlgorithm() != SKA_PLAIN_TEXT)
                {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    DecodedDataInfoPtr PGPDecrypt::DecryptMessage(PGPMessagePtr crypt_msg, PGPMessagePtr sec_key_ptr, const std::string& passphrase)
    {
        decoded_data_info_.reset(new DecodedDataInfo);
        
        PGPPacketsArray packets = crypt_msg->GetPackets();
        
        CharDataVector session_key_data;
        
        if (!ExtractSeessionKeyData(packets, sec_key_ptr, passphrase, session_key_data))
        {
            return nullptr;
        }
        
        for (auto iter = packets.begin(); iter != packets.end(); ++iter)
        {

            if (((*iter)->GetPacketType() == PT_SYMMETRIC_ENCRYTPED_AND_INTEGRITY_PROTECTED_DATA_PACKET)
                || ((*iter)->GetPacketType() == PT_SYMMETRICALLY_ENCRYPTED_DATA_PACKET))
            {
                SymmetricallyEncryptedDataPacketPtr packet_ptr = std::dynamic_pointer_cast<SymmetricallyEncryptedDataPacket>((*iter));
                bool flag = ((*iter)->GetPacketType() == PT_SYMMETRICALLY_ENCRYPTED_DATA_PACKET) ? true : false;
                SymmetricKeyDecrypt(session_key_data, packet_ptr->GetEncryptedData(), flag);
            }
        }
        
        return decoded_data_info_;
    }
    
    void PGPDecrypt::SymmetricKeyDecrypt(CharDataVector& session_key_data, const CharDataVector& encrypted_data, bool flag)
    {
        SymmetricKeyAlgorithms algo = static_cast<SymmetricKeyAlgorithms>(session_key_data[0]);
        crypto::SymmetricKeyAlgorithmPtr algo_impl = crypto::GetSymmetricKeyAlgorithm(algo);
        
        CharDataVector initial_vector(algo_impl->GetChiperBlockSize(), 0);
        
        CharDataVector session_key(session_key_data.begin() + 1, session_key_data.begin() + algo_impl->GetKeyLength() + 1);
        CharDataVector result_data;
        
        if (flag == true)
        {
            if (algo_impl->DecryptInOpenPGPCFBMode(encrypted_data, session_key, result_data, flag))
            {
                if (!IsDataDecryptedCorrect(result_data, algo_impl->GetChiperBlockSize()))
                {
                    // TODO: handle error
                    return;
                }
                
                //CharDataVector decrypted_data(result_data.begin() + algo_impl->GetChiperBlockSize() + 2, result_data.end());
                HandleDecryptedData(result_data, algo_impl->GetChiperBlockSize() + 2);
            }
        }
        else if (algo_impl->DecryptInCFBMode(encrypted_data, session_key, initial_vector, result_data))
        {
            if (!IsDataDecryptedCorrect(result_data, algo_impl->GetChiperBlockSize()))
            {
                // TODO: handle error
                return;
            }
            
            //CharDataVector decrypted_data(result_data.begin() + algo_impl->GetChiperBlockSize() + 2, result_data.end());
            HandleDecryptedData(result_data, algo_impl->GetChiperBlockSize() + 2);
        }
    }
        
    void PGPDecrypt::HandlePacket(CompressedDataPacketPtr compression_data_packet)
    {
        crypto::CompressionAlgorithmPtr algo_impl = crypto::GetCompressionAlgorithmImpl(compression_data_packet->GetCompressAlgorithm());
        if (!algo_impl)
        {
            return;
        }
        
        CharDataVector decompression_data;
        algo_impl->DecompressData(compression_data_packet->GetData(), decompression_data);
        
        if (decompression_data.empty())
        {
            return;
        }
        
        PGPPacketsParser parser(decompression_data);
        PGPPacketsArray packets = parser.ParsePackets();
        
        if (packets.empty())
        {
            return;
        }
        
        std::string plain_text;
        
        for (auto iter = packets.begin(); iter != packets.end(); ++iter)
        {
            switch ((*iter)->GetPacketType())
            {
                case PT_SIGNATURE_PACKET:
                    {
                        SignaturePacketPtr signature_data_packet = std::dynamic_pointer_cast<SignaturePacket>((*iter));
                        decoded_data_info_->is_signed_ = true;
                        
                        CharDataVector signature_data;
                        signature_data_packet->GetBinaryData(signature_data);
                        std::string base64data = Utils::Base64Encode(signature_data);
                        decoded_data_info_->signature_data = base64data;
                        
                        SignatureKeyInfo signature_key_info;
                        signature_key_info.keyID = signature_data_packet->GetKeyID();
                        signature_key_info.createdTime = signature_data_packet->GetCreationTime();
                        signature_key_info.expirationTime = signature_data_packet->GetExpiredSignatureTime();
                        
                        decoded_data_info_->signatureKeyInfo = signature_key_info;
                        //CheckSignature(signature_data_packet);
                    }
                    break;
                    
                case PT_LITERAL_DATA_PACKET:
                    {
                        LiteralDataPacketPtr literal_data_packet = std::dynamic_pointer_cast<LiteralDataPacket>((*iter));
                        
                        decoded_data_info_->decoded_data_.assign(literal_data_packet->GetData().begin(), literal_data_packet->GetData().end());
                        decoded_data_info_->file_name_.assign(literal_data_packet->GetFileName().begin(), literal_data_packet->GetFileName().end());
                    }

                    break;
                default:
                    break;
            }
        }
        

    }
        
    bool PGPDecrypt::HandleDecryptedData(const CharDataVector& decrypted_data, const int shift)
    {
        CharDataVector data_for_parse(decrypted_data.begin() + shift, decrypted_data.end());
        
        PGPPacketsParser parser(data_for_parse);
        PGPPacketsArray packets = parser.ParsePackets();
        
        if (packets.empty())
        {
            return false;
        }
        
        for (auto iter = packets.begin(); iter != packets.end(); ++iter)
        {
            switch ((*iter)->GetPacketType())
            {
                case PT_COMPRESSED_DATA_PACKET:
                    HandlePacket(std::dynamic_pointer_cast<CompressedDataPacket>((*iter)));
                    
                    break;
                    
                case PT_LITERAL_DATA_PACKET:
                    {
                        LiteralDataPacketPtr literal_data_packet = std::dynamic_pointer_cast<LiteralDataPacket>((*iter));
                        decoded_data_info_->decoded_data_.assign(literal_data_packet->GetData().begin(), literal_data_packet->GetData().end());

                        decoded_data_info_->file_name_.assign(literal_data_packet->GetFileName().begin(), literal_data_packet->GetFileName().end());
                    }
                    
                    break;
                    
                case PT_SIGNATURE_PACKET:
                    {
                        SignaturePacketPtr signature_data_packet = std::dynamic_pointer_cast<SignaturePacket>((*iter));
                        decoded_data_info_->is_signed_ = true;
                        decoded_data_info_->is_signed_ = DecodedDataInfo::DDI_SIGNATURE_FAILURE;
                        
                        CharDataVector signature_data;
                        signature_data_packet->GetBinaryData(signature_data);
                        std::string base64data = Utils::Base64Encode(signature_data);
                        decoded_data_info_->signature_data = base64data;
                        
                        SignatureKeyInfo signature_key_info;
                        signature_key_info.keyID = signature_data_packet->GetKeyID();
                        signature_key_info.createdTime = signature_data_packet->GetCreationTime();
                        signature_key_info.expirationTime = signature_data_packet->GetExpiredSignatureTime();
                        
                        decoded_data_info_->signatureKeyInfo = signature_key_info;
                        
                        //CheckSignature(signature_data_packet);
                    }
                    
                    break;
                    
                case PT_MODIFICATION_DETECTION_CODE_PACKET:
                    {
                        crypto::Sha1 sha1;
                        CharDataVector src(decrypted_data.begin(), decrypted_data.end() - 20);
            
                        CharDataVector dst;
                        sha1.Hash(src, dst);
                        
                        ModificationDetectionCodePacketPtr  mdc_packet = std::dynamic_pointer_cast<ModificationDetectionCodePacket>((*iter));
                        if (!std::equal(dst.begin(), dst.end(), mdc_packet->GetData().begin()))
                        {
                            // TODO: handle error
                            std::cout << "ERROR mdc checksum" << std::endl;
                            return false;
                        }
                        // TODO: CheckDataForModifications();
                        break;
                    }
                    
                default:
                    break;
            }
        }

        return true;
    }
    
    void PGPDecrypt::CheckSignature(SignaturePacketPtr signature_packet_ptr)
    {
        /*std::string public_key_str = pgp_info_getter_->GetPublicKeyByID(signature_packet_ptr->GetKeyID());
        
        PGPPacketsArray pgp_packets_array;
        pgp_packets_array.push_back(signature_packet_ptr);
        
        decoded_data_info_->is_signed_ = true;
        decoded_data_info_->state_ = DecodedDataInfo::DDI_SIGNATURE_FAILURE;
        
        PGPMessagePtr message_ptr(new PGPMessageImpl);
        message_ptr->SetPlainText(std::string(decoded_data_info_->decoded_data_.begin(), decoded_data_info_->decoded_data_.end()));
        message_ptr->SetPackets(pgp_packets_array);
        
        std::string public_key = pgp_info_getter_->GetPublicKeyByID(signature_packet_ptr->GetKeyID());
        if (public_key.empty())
        {
            decoded_data_info_->state_ = DecodedDataInfo::DDI_KEY_NOT_FOUND;
            return;
        }
        
        //decoded_data_info_->signature_ = crypto::CheckSignature(message_ptr, pgp_info_getter_);
        if ( decoded_data_info_->signature_  == true)
        {
            decoded_data_info_->state_ = DecodedDataInfo::DDI_SIGNATURE_VERIFIED;
        }*/
    }


}
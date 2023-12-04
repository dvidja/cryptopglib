//
//  OpenPGPImpl.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 19.6.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "open_pgp_impl.h"


#include "pgp_message_impl.h"
#include "pgp_parser/pgp_parser.h"

#include "pgp_data/packets/public_key_packet.h"
#include "pgp_data/packets/user_id_packet.h"
#include "pgp_data/packets/signature_packet.h"
#include "pgp_data/packets/one_pass_signature_packet.h"

#include "pgp_creator/pgp_creator.h"
#include "crypto/pgp_encrypt.h"
#include "crypto/key_generator.h"
#include "crypto/pgp_key_data.h"
#include "cryptopglib/pgp_errors.h"


#include "utils/base64.h"

#include <sstream>


namespace
{
    cryptopglib::crypto::SecretKeyPacketPtr GetSignaturePacketFromMessage(cryptopglib::PGPMessagePtr signature_key_ptr)
    {
        cryptopglib::crypto::SecretKeyPacketPtr packet;
        cryptopglib::PGPPacketsArray packets = signature_key_ptr->GetPackets();
        
        for (auto iter = packets.begin(); iter != packets.end(); ++iter)
        {
            if ((*iter)->GetPacketType() == cryptopglib::PacketType::kSecretKeyPacket)
            {
                packet = std::dynamic_pointer_cast<cryptopglib::pgp_data::packets::SecretKeyPacket>(*iter);
                return packet;
            }
        }
        
        return packet;
    }
    
    void RemoveLineEndings(cryptopglib::CharDataVector& data);

    void RemoveLineEndings(cryptopglib::CharDataVector &data) {
        cryptopglib::CharDataVector::iterator pos_iter = data.begin();
        do
        {
            pos_iter = std::find(pos_iter, data.end(), '\n');
            if (pos_iter == data.end())
            {
                return;
            }

            if (*(pos_iter - 1) == '\r')
            {
                data.erase(pos_iter - 1, pos_iter + 1);
            }
            else
            {
                data.erase(pos_iter);
            }
            if (pos_iter != data.begin())
            {
                pos_iter--;
            }
        }
        while (pos_iter != data.end());
    }

    bool IsPGPMessage(const cryptopglib::CharDataVector& data)
    {
        std::string input_data(data.begin(), data.end());
        //CharDataVector decoded_data = Utils::Base64Decode(input_data);
        
        //std::string temp_str(decoded_data.begin(), decoded_data.end());
        size_t pos = input_data.find("-----BEGIN PGP");
        
        return pos == std::string::npos ? false : true;
    }
    
    cryptopglib::pgp_data::packets::CompressedDataPacketPtr CompressData(const cryptopglib::CharDataVector& source, CompressionAlgorithms algo)
    {
        cryptopglib::crypto::CompressionAlgorithmPtr compress_algo_impl = cryptopglib::crypto::GetCompressionAlgorithmImpl(algo);
        
        if (compress_algo_impl == nullptr)
        {
            return nullptr;
        }
        cryptopglib::pgp_data::packets::CompressedDataPacketPtr compressed_data_packet(new cryptopglib::pgp_data::packets::CompressedDataPacket);
        compressed_data_packet->SetCompressAlgorithm(algo);
        
        cryptopglib::CharDataVector compressed_data;
        compress_algo_impl->CompressData(source, compressed_data);
        
        compressed_data_packet->SetData(compressed_data);
        
        return compressed_data_packet;
    }
}

namespace cryptopglib {

    OpenPGPImpl::OpenPGPImpl(OpenPGPInfoGetter *pgp_info_getter) {
        pgp_info_getter_.reset(pgp_info_getter);
    }

    OpenPGPImpl::~OpenPGPImpl() {
        std::cout << "OpenPGPImpl deleted" << std::endl;
    }

    PGPMessageType OpenPGPImpl::GetMessageType(const std::string &message) {
        pgp_parser::PGPParser message_parser;
        PGPMessagePtr message_ptr;
        try {
            message_ptr = message_parser.ParseMessage(message);
        }
        catch (PGPError &exp) {
            std::cout << exp.what() << std::endl;
        }

        if (message_ptr) {
            return message_ptr->GetMessageType();
        }

        return PGPMessageType::kIncorrectMessage;
    }

    KeyInfoImpl OpenPGPImpl::GetKeyInfo(const std::string& message) {
        pgp_parser::PGPParser pgp_parser;
        PGPMessagePtr message_ptr;

        try {
            message_ptr = pgp_parser.ParseMessage(message);
        }
        catch (PGPError &exp) {
            std::cout << exp.what() << std::endl;
        }

        if (message_ptr) {
            if ((message_ptr->GetMessageType() != PGPMessageType::kPublicKey)
                && (message_ptr->GetMessageType() != PGPMessageType::kPrivateKey)) {
                return KeyInfoImpl();
            }

            PGPPacketsArray packets = message_ptr->GetPackets();

            KeyInfoImpl key_info;
            for (auto iter = packets.begin(); iter != packets.end(); ++iter) {
                PacketType packet_type = static_cast<PacketType>((*iter)->GetPacketType());
                switch (packet_type) {
                    case PacketType::kPublicKeyPacket:
                    case PacketType::kPublicSubkeyPacket: {
                        pgp_data::packets::PublicKeyPacket *p = dynamic_cast<pgp_data::packets::PublicKeyPacket *>(iter->get());
                        if (p->GetPacketType() == PacketType::kPublicKeyPacket) {
                            key_info.key_type_ = p->GetPublicKeyAlgorithm();
                            key_info.created_time_ = p->GetTimestamp();
                            if (key_info.size_.empty()) {
                                key_info.size_ = std::to_string(p->GetKeySize());
                            } else {
                                key_info.size_.insert(0, std::to_string(p->GetKeySize()) + "/");
                            }
                        }

                        if (key_info.public_key_id_.size() == 0) {
                            key_info.public_key_id_ = p->GetKeyID();
                            key_info.key_fingerprint_ = p->GetFingerprint();
                        } else {
                            key_info.public_sub_keys_id_.push_back(p->GetKeyID());
                            key_info.sub_key_fingerprint_.push_back(p->GetFingerprint());
                        }

                        unsigned int expired = p->GetKeyExpiredTime();
                        if (expired != 0) {
                            key_info.expired_key_time_ = expired;
                        }
                    }
                        break;
                    case PacketType::kSecretKeyPacket:
                    case PacketType::kSecretSubkeyPacket: {
                        pgp_data::packets::SecretKeyPacket *p = dynamic_cast<pgp_data::packets::SecretKeyPacket *>(iter->get());
                        if (key_info.public_key_id_.size() == 0) {
                            key_info.public_key_id_ = p->GetKeyID();
                            key_info.key_fingerprint_ = p->GetPublicKeyPatr()->GetFingerprint();
                        } else {
                            key_info.public_sub_keys_id_.push_back(p->GetKeyID());
                            key_info.sub_key_fingerprint_.push_back(p->GetPublicKeyPatr()->GetFingerprint());
                        }

                        crypto::PublicKeyPacketPtr publicPart = p->GetPublicKeyPatr();
                        if (publicPart->GetPacketType() == PacketType::kPublicKeyPacket) {
                            key_info.key_type_ = publicPart->GetPublicKeyAlgorithm();
                            key_info.created_time_ = publicPart->GetTimestamp();
                            if (key_info.size_.empty()) {
                                key_info.size_ = std::to_string(publicPart->GetKeySize());
                            } else {
                                key_info.size_.insert(0, std::to_string(publicPart->GetKeySize()) + "/");
                            }
                        }

                        unsigned int expired = publicPart->GetKeyExpiredTime();
                        if (expired != 0) {
                            key_info.expired_key_time_ = expired;
                        }
                    }
                        break;
                    case PacketType::kUserIDPacket: {
                        pgp_data::packets::UserIDPacket *p = dynamic_cast<pgp_data::packets::UserIDPacket *>(iter->get());
                        key_info.users_id_.push_back(p->GetUserID());
                    }
                        break;
                    case PacketType::kSignaturePacket: {
                        pgp_data::packets::SignaturePacket *p = dynamic_cast<pgp_data::packets::SignaturePacket *>(iter->get());
                        unsigned int expired = p->GetExpiredKeyTime();
                        if (expired != 0) {
                            key_info.expired_key_time_ = expired;
                        }

                        KeyIDData keyID = p->GetKeyID();
                        bool already_exist = false;
                        for (int i = 0; i < key_info.signature_keys_info_.size(); ++i) {
                            if ((keyID[0] == key_info.signature_keys_info_[i].keyID[0]) &&
                                (keyID[1] == key_info.signature_keys_info_[i].keyID[1])) {
                                already_exist = true;
                                break;
                            }
                        }

                        if (!already_exist) {
                            crypto::SignatureKeyInfo signatureKeyInfo;
                            signatureKeyInfo.keyID = keyID;
                            signatureKeyInfo.createdTime = p->GetCreationTime();
                            signatureKeyInfo.expirationTime = p->GetExpiredSignatureTime();

                            key_info.signature_keys_info_.push_back(signatureKeyInfo);
                        }

                        if (p->GetPacketVersion() == 4) {
                            if (!p->GetPreferredHahAlgorithms().empty())
                                key_info.prefered_hash_algorithms_ = p->GetPreferredHahAlgorithms();
                            if (!p->GetPreferredCipherAlgorithms().empty())
                                key_info.prefered_chipers_ = p->GetPreferredCipherAlgorithms();
                            if (!p->GetPreferredCompressionAlgorithms().empty())
                                key_info.prefered_compression_algorithms_ = p->GetPreferredCompressionAlgorithms();
                        }
                    }
                        break;
                    default:
                        break;
                }
            }

            return key_info;
        }

        return KeyInfoImpl();
    }

    crypto::SignatureKeyInfo OpenPGPImpl::ReadSignatureMessage(const std::string &signature) {
        pgp_parser::PGPParser pgp_parser;
        PGPMessagePtr message_ptr;


        crypto::SignatureKeyInfo signature_key_info;

        try {
            message_ptr = pgp_parser.ParseMessage(signature);
        }
        catch (PGPError &exp) {
            std::cout << exp.what() << std::endl;
            return signature_key_info;
        }

        if (!message_ptr) {
            return signature_key_info;
        }

        if (message_ptr->GetMessageType() != PGPMessageType::kSignedMessage) {
            return signature_key_info;
        }

        signature_key_info = crypto::GetSignatureKeyID(message_ptr);
        return signature_key_info;

    }

    crypto::SignatureResultInfo OpenPGPImpl::CheckSignature(const std::string &message, const std::string &public_key) {
        pgp_parser::PGPParser pgp_parser;
        PGPMessagePtr message_ptr;

        crypto::SignatureResultInfo signature_result_info;

        try {
            message_ptr = pgp_parser.ParseMessage(message);
        }
        catch (PGPError &exp) {
            std::cout << exp.what() << std::endl;
            signature_result_info.signature_result_ = crypto::SR_NONE_SIGNATURE;
            return signature_result_info;
        }

        if (!message_ptr) {
            signature_result_info.signature_result_ = crypto::SR_NONE_SIGNATURE;
            return signature_result_info;
        }

        return crypto::CheckSignature(message_ptr, public_key);
    }

    crypto::SignatureResultInfo OpenPGPImpl::CheckSignature(const std::string &signature, const std::string &plain_text,
                                                    const std::string &public_key) {
        pgp_parser::PGPParser pgp_parser;
        PGPMessagePtr message_ptr;

        crypto::SignatureResultInfo signature_result_info;

        try {
            message_ptr = pgp_parser.ParseMessage(signature);
        }
        catch (PGPError &exp) {
            std::cout << exp.what() << std::endl;
            signature_result_info.signature_result_ = crypto::SR_NONE_SIGNATURE;
            return signature_result_info;
        }

        if (!message_ptr) {
            signature_result_info.signature_result_ = crypto::SR_NONE_SIGNATURE;
            return signature_result_info;
        }

        message_ptr->SetPlainText(plain_text);

        signature_result_info = crypto::CheckSignature(message_ptr, public_key);

        return signature_result_info;
    }

    std::string
    OpenPGPImpl::SignMessage(const std::string &message, const std::string &key, const std::string &passhprase,
                             const int hash_algo, bool armored) {
        pgp_parser::PGPParser parser;
        PGPMessagePtr private_key;

        try {
            private_key = parser.ParseMessage(key);
            if (!crypto::PGPKeyDataDecrypt(private_key, passhprase)) {
                return std::string();
            }
        }
        catch (PGPError &exp) {
            std::cout << exp.what() << std::endl;
            return "";
        }

        if (!private_key) {
            return std::string();
        }

        if (private_key->GetMessageType() != PGPMessageType::kPrivateKey) {
            return std::string();
        }

        PGPMessagePtr signed_message = crypto::SignMessage(message,
                                                           private_key,
                                                           static_cast<HashAlgorithms>(hash_algo));

        if (!signed_message) {
            return std::string();
        }

        CharDataVector signature_message_data;
        pgp_creator::PGPCreator::GetBinaryRepresentationOfMessage(signed_message, signature_message_data, armored);

        std::string resul_string(signature_message_data.begin(), signature_message_data.end());

        return resul_string;
    }

    void OpenPGPImpl::GetSecretKeyIDForCryptoMessage(const std::string &message, std::vector<KeyIDData> &key_ids) {
        pgp_parser::PGPParser pgp_parser;
        PGPMessagePtr message_ptr;

        try {
            message_ptr = pgp_parser.ParseMessage(message);
        }
        catch (PGPError &exp) {
            std::cout << exp.what() << std::endl;
            return;
        }

        if (!message_ptr) {
            return;
        }

        if (message_ptr->GetMessageType() == PGPMessageType::kEncryptedMessage) {
            crypto::PGPDecrypt decryptor(pgp_info_getter_);
            decryptor.GetSecretKeyID(message_ptr, key_ids);
        }
    }

    bool OpenPGPImpl::IsSecretKeyEncrypted(const std::string &message) {
        pgp_parser::PGPParser pgp_parser;
        PGPMessagePtr message_ptr = pgp_parser.ParseMessage(message);

        try {
            message_ptr = pgp_parser.ParseMessage(message);
        }
        catch (PGPError &exp) {
            std::cout << exp.what() << std::endl;
            return false;
        }

        if (!message_ptr) {
            return false;
        }

        if (message_ptr->GetMessageType() == PGPMessageType::kPrivateKey) {
            crypto::PGPDecrypt decryptor(pgp_info_getter_);
            return decryptor.IsSecretKeyEncoded(message_ptr);
        }

        return false;
    }

    crypto::DecodedDataInfoPtr OpenPGPImpl::DecryptMessage(const std::string &message, const std::string &secret_key,
                                                   const std::string &passphrase) {
        pgp_parser::PGPParser pgp_parser;
        PGPMessagePtr message_ptr;
        PGPMessagePtr sec_key_ptr;

        try {
            message_ptr = pgp_parser.ParseMessage(message);
            sec_key_ptr = pgp_parser.ParseMessage(secret_key);
            if (!crypto::PGPKeyDataDecrypt(sec_key_ptr, passphrase)) {
                return nullptr;
            }
        }
        catch (PGPError &exp) {
            std::cout << exp.what() << std::endl;
            return nullptr;
        }

        if ((!message_ptr) || (!sec_key_ptr)) {
            return nullptr;
        }

        if ((message_ptr->GetMessageType() == PGPMessageType::kEncryptedMessage)
            && (sec_key_ptr->GetMessageType() == PGPMessageType::kPrivateKey)) {
            crypto::PGPDecrypt decryptor(pgp_info_getter_);
            crypto::DecodedDataInfoPtr decoded_data_info = decryptor.DecryptMessage(message_ptr, sec_key_ptr, passphrase);

            return decoded_data_info;
        }

        return nullptr;
    }

    crypto::DecodedDataInfoPtr
    OpenPGPImpl::DecryptMessage(const std::string &message, std::vector<CharDataVector> attached_data,
                                const std::string &secret_key, const std::string &passphrase) {
        pgp_parser::PGPParser pgp_parser;
        PGPMessagePtr message_ptr;
        PGPMessagePtr sec_key_ptr;
        std::vector<PGPMessagePtr> attached_messages;
        try {
            message_ptr = pgp_parser.ParseMessage(message);
            sec_key_ptr = pgp_parser.ParseMessage(secret_key);
            if (!crypto::PGPKeyDataDecrypt(sec_key_ptr, passphrase)) {
                return nullptr;
            }

            for (size_t i = 0; i < attached_data.size(); ++i) {
                CharDataVector data(attached_data[i].begin(), attached_data[i].end());
                //RemoveLineEndings(data);

                if (IsPGPMessage(data)) {
                    std::string input_data(data.begin(), data.end());
                    //CharDataVector decoded_data = Utils::Base64Decode(input_data);
                    std::string temp_data(data.begin(), data.end());

                    PGPMessagePtr attached_message_ptr = pgp_parser.ParseMessage(temp_data);
                    attached_messages.push_back(attached_message_ptr);
                } else {
                    PGPMessagePtr attached_message_ptr(new PGPMessageImpl);
                    //std::string base64_data = Utils::Base64Encode(data);
                    //attached_message_ptr->SetBase64Data(base64_data);
                    pgp_parser::PGPPacketsParser packet_parser(data);
                    PGPPacketsArray packets = packet_parser.ParsePackets();
                    attached_message_ptr->SetPackets(packets);

                    attached_messages.push_back(attached_message_ptr);
                }
            }
        }
        catch (PGPError &exp) {
            std::cout << exp.what() << std::endl;
            return nullptr;
        }

        if ((!message_ptr) || (!sec_key_ptr)) {
            return nullptr;
        }

        if ((message_ptr->GetMessageType() == PGPMessageType::kEncryptedMessage)
            && (sec_key_ptr->GetMessageType() == PGPMessageType::kPrivateKey)) {
            crypto::PGPDecrypt decryptor(pgp_info_getter_);
            crypto::DecodedDataInfoPtr decoded_data_info = decryptor.DecryptMessage(message_ptr, sec_key_ptr, passphrase);

            for (size_t i = 0; i < attached_messages.size(); ++i) {
                crypto::DecodedDataInfoPtr decoded_data_temp = decryptor.DecryptMessage(attached_messages[i], sec_key_ptr,
                                                                                passphrase);
                if (decoded_data_temp) {
                    decoded_data_info->attached_data_.push_back(decoded_data_temp);
                }
            }

            return decoded_data_info;
        }

        return nullptr;
    }

    crypto::SignatureResultInfo
    OpenPGPImpl::CheckSignatureForDecryptedData(const CharDataVector &data, const std::string &signature,
                                                const std::string &public_key) {
        CharDataVector signature_data = utils::Base64Decode(signature);
        pgp_parser::PGPPacketsParser pacekt_parser(signature_data);

        crypto::SignatureResultInfo signature_result;

        PGPPacketsArray packets = pacekt_parser.ParsePackets();
        if (packets.empty()) {
            signature_result.signature_result_ = crypto::SR_NONE_SIGNATURE;
            return signature_result;
        }

        if (packets[0]->GetPacketType() != PacketType::kSignaturePacket) {
            signature_result.signature_result_ = crypto::SR_NONE_SIGNATURE;
            return signature_result;
        }

        crypto::SignaturePacketPtr signature_packet_ptr = std::dynamic_pointer_cast<pgp_data::packets::SignaturePacket>(packets[0]);

        signature_result.signature_result_ = crypto::CheckSignature(data, signature_packet_ptr, public_key);
        signature_result.create_signature_time_ = signature_packet_ptr->GetCreationTime();
        signature_result.expired_signature_time_ = signature_packet_ptr->GetExpiredSignatureTime();

        return signature_result;
    }

    std::string
    OpenPGPImpl::EncryptData(const std::string &plain_text, const std::vector<std::string> &addressers_public_keys,
                             const std::string &own_public_key) {
        pgp_parser::PGPParser pgp_parser;
        std::vector<PGPMessagePtr> addressers_pub_keys_ptr;
        PGPMessagePtr ownr_key_ptr;

        try {
            for (std::string pub_key: addressers_public_keys) {
                PGPMessagePtr addresser_pub_key_ptr = pgp_parser.ParseMessage(pub_key);
                if (addresser_pub_key_ptr) {
                    addressers_pub_keys_ptr.push_back(addresser_pub_key_ptr);
                }
            }

            ownr_key_ptr = pgp_parser.ParseMessage(own_public_key);
        }
        catch (PGPError &exp) {
            std::cout << exp.what() << std::endl;
            return "";
        }

        if ((addressers_pub_keys_ptr.empty()) || (ownr_key_ptr == nullptr)) {
            return std::string();
        }

        crypto::PGPEncrypt encryptor;
        PGPMessagePtr encrypted_message = encryptor.EncryptMessage(plain_text, addressers_pub_keys_ptr, ownr_key_ptr,
                                                                   pgp_info_getter_);

        CharDataVector data;
        pgp_creator::PGPCreator::GetBinaryRepresentationOfMessage(encrypted_message, data);

        return std::string(data.begin(), data.end());
    }

    KeyPairImpl OpenPGPImpl::GenerateKeyPair(const std::string &email, const std::string &passphrase) {
        crypto::TransferingKeysPtr transfering_keys_ptr = crypto::GenerateSecretKey(email, passphrase, kRSA, 2048);
        if (transfering_keys_ptr == nullptr) {
            return KeyPairImpl();
        }

        CharDataVector public_key_data;
        pgp_creator::PGPCreator::GetBinaryRepresentationOfMessage(transfering_keys_ptr->public_key, public_key_data);

        KeyPairImpl key_pair;
        key_pair.public_key = std::string(public_key_data.begin(), public_key_data.end());

        CharDataVector private_key_data;
        pgp_creator::PGPCreator::GetBinaryRepresentationOfMessage(transfering_keys_ptr->private_key, private_key_data);

        key_pair.secret_key = std::string(private_key_data.begin(), private_key_data.end());

        return key_pair;
    }

    std::string
    OpenPGPImpl::EncryptAndSignMessage(const std::string &message, const std::vector<std::string> &encrypt_keys,
                                       const std::string &sign_key, const std::string &passphrase) {
        pgp_parser::PGPParser pgp_parser;
        PGPMessagePtr signature_key_ptr;
        std::vector<PGPMessagePtr> encrypt_keys_ptr;

        try {
            signature_key_ptr = pgp_parser.ParseMessage(sign_key);

            if (!crypto::PGPKeyDataDecrypt(signature_key_ptr, passphrase)) {
                return std::string();
            }

            for (std::string pub_key: encrypt_keys) {
                PGPMessagePtr addresser_pub_key_ptr = pgp_parser.ParseMessage(pub_key);
                if (addresser_pub_key_ptr) {
                    encrypt_keys_ptr.push_back(addresser_pub_key_ptr);
                }
            }

        }
        catch (PGPError &exp) {
            std::cout << exp.what() << std::endl;
            return std::string();
        }

        if ((encrypt_keys_ptr.empty()) || (!signature_key_ptr)) {
            return std::string();
        }

        CharDataVector data_for_sign(message.begin(), message.end());

        pgp_data::packets::LiteralDataPacket literal_data_packet;
        literal_data_packet.SetData(data_for_sign);

        crypto::SecretKeyPacketPtr secret_key_ptr = GetSignaturePacketFromMessage(signature_key_ptr);
        crypto::SignaturePacketPtr signature_packet_ptr = crypto::SignRawData(data_for_sign, secret_key_ptr,
                                                                      (HashAlgorithms) pgp_info_getter_->GetHashAlgorithmForSign());

        if (signature_packet_ptr == nullptr) {
            std::cout << "Signature calculation error" << std::endl;
            return "";
        }

        pgp_data::packets::OnePassSignaturePacketPtr one_pass_signature_packet(new pgp_data::packets::OnePassSignaturePacket(signature_packet_ptr));

        CharDataVector data_for_compress;
        one_pass_signature_packet->GetBinaryData(data_for_compress);

        CharDataVector temp;
        literal_data_packet.GetBinaryData(temp);
        data_for_compress.insert(data_for_compress.end(), temp.begin(), temp.end());

        temp.clear();
        signature_packet_ptr->GetBinaryData(temp);
        data_for_compress.insert(data_for_compress.end(), temp.begin(), temp.end());

        if (data_for_compress.empty()) {
            return std::string();
        }

        CharDataVector data_for_encrypt;
        CompressionAlgorithms compress_algo = static_cast<CompressionAlgorithms>(pgp_info_getter_->GetCompressAlgorithm());
        if (compress_algo == CA_UNCOMPRESSED) {
            data_for_encrypt.assign(data_for_compress.begin(), data_for_compress.end());
        } else {
            pgp_data::packets::CompressedDataPacketPtr compressed_data_packet = CompressData(data_for_compress, compress_algo);
            compressed_data_packet->GetBinaryData(data_for_encrypt);
        }

        if (data_for_encrypt.empty()) {
            return std::string();
        }

        crypto::PGPEncrypt encryptor;
        PGPMessagePtr encrypted_message_ptr = encryptor.EncryptRawData(data_for_encrypt, encrypt_keys_ptr,
                                                                       signature_key_ptr, pgp_info_getter_);
        if (!encrypted_message_ptr) {
            return std::string();
        }

        pgp_creator::PGPCreator pgp_creator;
        CharDataVector result_data;
        pgp_creator.GetBinaryRepresentationOfMessage(encrypted_message_ptr, result_data);
        if (result_data.empty()) {
            return std::string();
        }

        std::string result(result_data.begin(), result_data.end());
        return result;
    }

    bool OpenPGPImpl::IsPassphraseCorrect(const std::string &secret_key, const std::string &passphrase) {
        pgp_parser::PGPParser pgp_parser;
        PGPMessagePtr sec_key_ptr;

        try {
            sec_key_ptr = pgp_parser.ParseMessage(secret_key);
            if (sec_key_ptr == nullptr) {
                return false;
            }

            if (!crypto::PGPKeyDataDecrypt(sec_key_ptr, passphrase)) {
                return false;
            }
        }
        catch (PGPError &exp) {
            std::cout << exp.what() << std::endl;
            return false;
        }

        return true;
    }

    crypto::CheckSignatureResult
    OpenPGPImpl::CheckKeySignature(const std::string &signed_key, const std::string &verification_key) {
        return crypto::CheckKeySignature(signed_key, verification_key);
    }

    std::string OpenPGPImpl::SignPublicKey(const std::string &public_key, const std::string &private_key,
                                           const std::string &passphrase) {
        pgp_parser::PGPParser parser;
        PGPMessagePtr private_key_message;

        try {
            private_key_message = parser.ParseMessage(private_key);
            if (!private_key_message) {
                return std::string();
            }

            if (!crypto::PGPKeyDataDecrypt(private_key_message, passphrase)) {
                return std::string();
            }
        }
        catch (PGPError &exp) {
            std::cout << exp.what() << std::endl;
            return "";
        }

        if (private_key_message->GetMessageType() != PGPMessageType::kPrivateKey) {
            return std::string();
        }

        PGPMessagePtr public_key_message = parser.ParseMessage(public_key);
        if (!public_key_message) {
            return std::string();
        }

        PGPMessagePtr signed_public_key = crypto::SignPublicKey(public_key_message, private_key_message);

        if (!signed_public_key) {
            return std::string();
        }

        CharDataVector signature_message_data;
        pgp_creator::PGPCreator::GetBinaryRepresentationOfMessage(signed_public_key, signature_message_data, true);

        std::string result_string(signature_message_data.begin(), signature_message_data.end());

        return result_string;
    }

    std::string OpenPGPImpl::ChangePassphrase(const std::string &private_key, const std::string &old_passwd,
                                              const std::string &new_passwd) {
        pgp_parser::PGPParser parser;
        PGPMessagePtr private_key_message;

        try {
            private_key_message = parser.ParseMessage(private_key);
            if (!private_key_message) {
                return std::string();
            }

            if (!crypto::PGPKeyDataDecrypt(private_key_message, old_passwd)) {
                return std::string();
            }
        }
        catch (PGPError &exp) {
            std::cout << exp.what() << std::endl;
            return "";
        }

        if (private_key_message->GetMessageType() != PGPMessageType::kPrivateKey) {
            return std::string();
        }

        crypto::PGPKeyDataEncrypt(private_key_message, new_passwd);

        CharDataVector data;
        pgp_creator::PGPCreator::GetBinaryRepresentationOfMessage(private_key_message, data, true);

        std::string result_string(data.begin(), data.end());

        return result_string;
    }
}
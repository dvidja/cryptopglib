//
//  KeyGenerator.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 9.7.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "KeyGenerator.h"
extern "C" {
#include <openssl/rsa.h>
#include "openssl/dsa.h"
#include "openssl/rand.h"
#include "openssl/des.h"
}
#include "../PGPData/Packets/SecretKeyPacket.h" 
#include "../PGPData/Packets/PublicKeyPacket.h"
#include "../PGPData/Packets/SignaturePacket.h"
#include "../PGPData/Packets/UserIDPacket.h"
#include "PGPSignature.h"
#include "PublicKeyAlgorithmsImpl.h"
#include "PGPDecrypt.h"
#include "PGPKeyData.h"

#include <time.h>

#include <numeric>


namespace
{
    size_t GetMPIDataLength(DataBuffer& data_buffer)
    {
        int l = data_buffer.GetNextTwoOctets();
        l = (l + 7) / 8;
        
        return l;
    }
    
    void ReloadMPIs(SecretKeyPacketPtr secret_key_packet_ptr)
    {
        DataBuffer data_buffer(secret_key_packet_ptr->GetMPI(0));
        secret_key_packet_ptr->ClearMPIData();
        
        size_t length = GetMPIDataLength(data_buffer);
        secret_key_packet_ptr->AddMPI(data_buffer.GetRange(length));
        
        length = GetMPIDataLength(data_buffer);
        secret_key_packet_ptr->AddMPI(data_buffer.GetRange(length));
        
        length = GetMPIDataLength(data_buffer);
        secret_key_packet_ptr->AddMPI(data_buffer.GetRange(length));
        
        length = GetMPIDataLength(data_buffer);
        secret_key_packet_ptr->AddMPI(data_buffer.GetRange(length));
    }
    
    /// NOTE!!! Methood dublicated in PGPParser.cpp
    bool GetDataForKeySignature(SignaturePacketPtr signature_packet, PublicKeyPacketPtr signed_public_key_packet, UserIDPacketPtr signed_user_id_packet, CharDataVector& data)
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
    
    bool GetDataForKeySignature(SignaturePacketPtr signature_packet, PublicKeyPacketPtr public_key_packet, PublicKeyPacketPtr public_subkey_packet, CharDataVector& data)
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
    
    bool CalculateKeyID(PublicKeyPacketPtr public_key_packet_ptr)
    {
        CharDataVector fingerprint;
        fingerprint.push_back(0x99);
        
        CharDataVector tmp_data;
        public_key_packet_ptr->GetRawData(tmp_data);
        
        size_t length = tmp_data.size();
        
        int a1 = length & 0xFF;
        int a2 = (length >> 8) & 0xFF;
        fingerprint.push_back(a2);
        fingerprint.push_back(a1);
        fingerprint.insert(fingerprint.end(), tmp_data.begin(), tmp_data.begin() + length);
        
        CharDataVector hash;
        crypto::Sha1 sha1;
        if (!sha1.Hash(fingerprint, hash))
        {
            return false;
        }
        
        size_t hash_size = hash.size();
        unsigned int id1 = 0;
        id1 = hash[hash_size - 8] << 24;
        id1 |= hash[hash_size - 7] << 16;
        id1 |= hash[hash_size - 6] << 8;
        id1 |= hash[hash_size - 5];
        
        unsigned int id2 = 0;
        id2 = hash[hash_size - 4] << 24;
        id2 |= hash[hash_size - 3] << 16;
        id2 |= hash[hash_size - 2] << 8;
        id2 |= hash[hash_size - 1];
        
        KeyIDData key_id = {id1, id2};
        public_key_packet_ptr->SetKeyID(key_id);
        
        return true;
    }
    
    void GetMPIsDataVector(const RSA* rsa_secret_key, CharDataVector& data)
    {
        std::vector<CharDataVector> mpis;

        auto d = RSA_get0_d(rsa_secret_key);
        CharDataVector mpi_d((BN_num_bytes(d)) * sizeof(char));
        int res = BN_bn2bin(d, &mpi_d[0]);
        mpis.push_back(mpi_d);

        auto p = RSA_get0_p(rsa_secret_key);
        CharDataVector mpi_p((BN_num_bytes(p)) * sizeof(char));
        res = BN_bn2bin(p, &mpi_p[0]);
        mpis.push_back(mpi_p);

        auto q = RSA_get0_q(rsa_secret_key);
        CharDataVector mpi_q((BN_num_bytes(q)) * sizeof(char));
        res = BN_bn2bin(q, &mpi_q[0]);
        mpis.push_back(mpi_q);
        
        BN_CTX* ctx = BN_CTX_new();
        BIGNUM* u = BN_mod_inverse(NULL, p, q, ctx);

        CharDataVector mpi_iqmp((BN_num_bytes(u)) * sizeof(char));
        res = BN_bn2bin(u, &mpi_iqmp[0]);
        mpis.push_back(mpi_iqmp);

        
        for (auto iter = mpis.begin(); iter != mpis.end(); ++iter)
        {
            size_t mpi_size = iter->size();
            mpi_size *= 8;
            
            double t = (*iter)[0];
            int bits = packet_helper::log2(t) + 1;
            int delta = 8 - bits;
            mpi_size -= delta;
            
            data.push_back((mpi_size >> 8) & 0xFF);
            data.push_back(mpi_size & 0xFF);
            data.insert(data.end(), iter->begin(), iter->end());
        }
    }
    
    bool EncryptData(const CharDataVector& encoded_data, const std::string& passphrase, const CharDataVector& salt, CharDataVector& initial_vector, int count, CharDataVector& result_data)
    {
        crypto::HashAlgorithmPtr hash_impl = crypto::GetHashImpl(HA_SHA1);
        crypto::SymmetricKeyAlgorithmPtr sym_key_algo_impl = crypto::GetSymmetricKeyAlgorithm(SKA_AES_256);
        if (!hash_impl && !sym_key_algo_impl)
        {
            return false;
        }
        
        std::vector<CharDataVector> hashes;
        std::vector<crypto::HashAlgorithmPtr> hashes_impl;
        for(int n = 0 ;  n * hash_impl->GetDigestLength() < sym_key_algo_impl->GetKeyLength(); ++n)
	    {
            hashes.push_back(CharDataVector());
            hashes_impl.push_back(crypto::GetHashImpl(HA_SHA1));
            hashes_impl[n]->Init();
            for(int i = 0 ; i < n ; ++i)
            {
                hashes[n].push_back(0);
                CharDataVector dat = {0};
                hashes_impl[n]->Update(dat);
            }
	    }
        
        for(int n = 0 ; n * hash_impl->GetDigestLength() < sym_key_algo_impl->GetKeyLength(); ++n)
	    {
            for(int i = 0 ; i < count ; i += passphrase.size() + salt.size())
            {
                int j = static_cast<int>(passphrase.size()) + static_cast<int>(salt.size());
                
                if(i + j > count && i != 0)
                {
                    j = count - i;
                }
                
                CharDataVector data(salt.begin(),
                                    salt.begin() + (j > salt.size() ? salt.size() : j));
                
                hashes_impl[n]->Update(data);
                
                if (j > salt.size())
                {
                    CharDataVector data(passphrase.begin(),
                                        passphrase.begin() + (j - salt.size()));
                    hashes_impl[n]->Update(data);
                    
                }
            }
	    }
        
        std::vector<CharDataVector> hashes_result(hashes.size());
        std::vector<CharDataVector> hashes_result_new(hashes.size());
        
        for(int n = 0 ; n * hash_impl->GetDigestLength() < sym_key_algo_impl->GetKeyLength(); ++n)
        {
            hash_impl->Hash(hashes[n], hashes_result[n]);
            hashes_impl[n]->Final(hashes_result_new[n]);
        }
        
        CharDataVector session_key(sym_key_algo_impl->GetKeyLength());
        
        for (int i = 0, n = 0, j = 0; i < session_key.size(); ++i)
        {
            if (j >= hashes_result_new[n].size())
            {
                j = 0;
                ++n;
            }
            
            session_key[i] = hashes_result_new[n][j];
            ++j;
        }
        
        //sym_key_algo_impl->DecryptInCFBMode(secret_key->GetMPI(0), session_key, secret_key->GetInitialVector(), result_data);
        sym_key_algo_impl->EncryptInCFBMode(encoded_data, session_key, initial_vector, result_data);
        if (result_data.empty())
        {
            // TODO : handle error Decrypt error
            return false;
        }
        
        return  true;
    }
    
    SecretKeyPacketPtr GenerateSecretKeyPacket(PublicKeyAlgorithms pub_key_algo, const std::string& passphrase, const int num_bits, bool is_subkey = false)
    {
        PublicKeyPacketPtr public_key_packet_ptr(new PublicKeyPacket(4, is_subkey));
        public_key_packet_ptr->SetTimestamp(static_cast<unsigned int>(time(NULL)));
        public_key_packet_ptr->SetPublicKeyAlgorithm(pub_key_algo);
        
        switch (pub_key_algo)
        {
            case PKA_RSA:
            case PKA_RSA_SIGN_ONLY:
            case PKA_RSA_ENCRYPT_ONLY:
                {
                    int rsa_exponent = 65537;
                    RSA* rsa_secret_key = RSA_generate_key(num_bits, rsa_exponent, 0, 0);

                    auto n = RSA_get0_n(rsa_secret_key);
                    CharDataVector mpi_n((BN_num_bytes(n)) * sizeof(char));
                    int res = BN_bn2bin(n, &mpi_n[0]);
                    public_key_packet_ptr->AddMPI(mpi_n);

                    auto e = RSA_get0_e(rsa_secret_key);
                    CharDataVector mpi_e((BN_num_bytes(e)) * sizeof(char));
                    res = BN_bn2bin(e, &mpi_e[0]);
                    public_key_packet_ptr->AddMPI(mpi_e);
                    
                    /// calculate key id
                    CalculateKeyID(public_key_packet_ptr);
                    
                    SecretKeyPacketPtr secret_key_packet_ptr(new SecretKeyPacket(public_key_packet_ptr));
                    
                    if (!passphrase.empty())
                    {
                        secret_key_packet_ptr->SetStringToKeyUsage(254);
                        secret_key_packet_ptr->SetSymmetricKeyAlgorithm(SKA_AES_256);
                        secret_key_packet_ptr->SetStringToKeySpecefier(3);
                        secret_key_packet_ptr->SetStringToKeyHashAlgorithm(HA_SHA1);
                        
                        CharDataVector salt;
                        crypto::GenerateSessionKey(8, salt, -1);
                        secret_key_packet_ptr->SetSaltValue(salt); // 8 bytes
                        
                        int count = 168;
                        secret_key_packet_ptr->SetCount(count);// one byte = 168 from another key
                        
                        crypto::SymmetricKeyAlgorithmPtr sym_key_algo_impl = crypto::GetSymmetricKeyAlgorithm(SKA_AES_256);
                        CharDataVector initial_vector;
                        crypto::GenerateSessionKey(sym_key_algo_impl->GetChiperBlockSize(), initial_vector, -1);
                        secret_key_packet_ptr->SetInitialVector(initial_vector);
                        
                        CharDataVector mpis_data_vector;
                        GetMPIsDataVector(rsa_secret_key, mpis_data_vector);
                        
                        crypto::HashAlgorithmPtr hash_algo_impl = crypto::GetHashImpl(HA_SHA1);
                        CharDataVector hash_checksum;
                        hash_algo_impl->Hash(mpis_data_vector, hash_checksum);
                        mpis_data_vector.insert(mpis_data_vector.end(), hash_checksum.begin(), hash_checksum.end());

                        CharDataVector encoded_data;
                        EncryptData(mpis_data_vector, passphrase, salt, initial_vector, secret_key_packet_ptr->GetCount(), encoded_data);
                        secret_key_packet_ptr->AddMPI(encoded_data); // encoded mpis
                    }
                    else
                    {
                        secret_key_packet_ptr->SetStringToKeyUsage(0);
                        secret_key_packet_ptr->SetStringToKeyHashAlgorithm(HA_NO_HASH);
                        secret_key_packet_ptr->SetStringToKeySpecefier(0);
                        
                        CharDataVector mpis;
                        GetMPIsDataVector(rsa_secret_key, mpis);
                        
                        int checksum = std::accumulate(mpis.begin(), mpis.end(), 0);
                        checksum = checksum % 65536;

                        mpis.push_back((checksum >> 8) & 0xff);
                        mpis.push_back(checksum & 0xff);
                        
                        secret_key_packet_ptr->AddMPI(mpis);
                    }
                    
                    RSA_free(rsa_secret_key);
                    
                    return secret_key_packet_ptr;
                }
                break;
                
            case PKA_ELGAMAL:
                {
                    
                }
                break;
            case PKA_DSA:
                {
                    
                }
                break;
            default:
                break;
        }
        
        return nullptr;
    }
}

namespace crypto
{
    TransferingKeysPtr GenerateSecretKey(const std::string& user_email, const std::string& passphrase, PublicKeyAlgorithms pub_key_algo, const int num_bits)
    {
        /// PRIMARY KEY
        
        SecretKeyPacketPtr secret_key_packet_ptr = GenerateSecretKeyPacket(pub_key_algo, passphrase, num_bits);
        if (secret_key_packet_ptr == nullptr)
        {
            return nullptr;
        }
        
        PGPMessagePtr secret_key_message(new PGPMessageImpl);
        secret_key_message->SetMessageType(PGPMessageType::MT_PRIVATE_KEY);
        PGPMessagePtr public_key_message(new PGPMessageImpl);
        public_key_message->SetMessageType(PGPMessageType::MT_PUBLIC_KEY);
        secret_key_message->AddPacket(secret_key_packet_ptr);
        public_key_message->AddPacket(secret_key_packet_ptr->GetPublicKeyPatr());
        
        UserIDPacketPtr user_id_packet_ptr(new UserIDPacket);
        CharDataVector user_id(user_email.begin(), user_email.end());
        user_id_packet_ptr->SetUserID(user_id);
        secret_key_message->AddPacket(user_id_packet_ptr);
        public_key_message->AddPacket(user_id_packet_ptr);
        
        SecretKeyPacketPtr key_for_self_signature;
        
        { // TODO extract to method
            
            SecretKeyPacketPtr temp_secret_key(new SecretKeyPacket(*secret_key_packet_ptr));
            if (!crypto::DecryptSecretKeyPacketData(temp_secret_key, passphrase))
            {
                if (!passphrase.empty())
                {
                    return nullptr;
                }
                
                ReloadMPIs(temp_secret_key);
            }

            SignaturePacketPtr signature_packet_ptr(new SignaturePacket(4));
            signature_packet_ptr->SetCreationTime(static_cast<unsigned int>(time(NULL)));
            signature_packet_ptr->SetHashAlgorithm(HA_SHA256);
            signature_packet_ptr->SetPublicKeyAlgorithm(PKA_RSA);
            KeyIDData key_id = secret_key_packet_ptr->GetKeyID();
            signature_packet_ptr->SetKeyID(key_id);
            signature_packet_ptr->SetSignatureType(16);
            
            /// add subpackets
            
            /// Notation data subpacket
            CharDataVector notation_data = {0x80, 0x0, 0x0, 0x0, 0x0, 0x20, 0x0, 0x7, 0x70, 0x72,
                                            0x65, 0x66, 0x65, 0x72, 0x72, 0x65, 0x64, 0x2d, 0x65,
                                            0x6d, 0x61, 0x69, 0x6c, 0x2d, 0x65, 0x6e, 0x63, 0x6f,
                                            0x64, 0x69, 0x6e, 0x67, 0x40, 0x70, 0x67, 0x70, 0x2e,
                                            0x63, 0x6f, 0x6d, 0x70, 0x67, 0x70, 0x6d, 0x69, 0x6d,
                                            0x65};
                                        
            signature_packet_ptr->AddSubpacketData(SST_NOTATION_DATA, notation_data, true);
            
            /// Preferred symmetric key algorithm subpacket
            CharDataVector prefered_sym_algos = {0x9, 0x8, 0x7, 0x3, 0x2, 0x1, 0xa};
            signature_packet_ptr->AddSubpacketData(SST_PREFERRED_SYMMETRIC_ALGO, prefered_sym_algos, true);
            
            /// primary user id subpacket
            CharDataVector primary_user_id_data = {0x1};
            signature_packet_ptr->AddSubpacketData(SST_PRIMARY_USER_ID, primary_user_id_data, true);
            
            //Key flags subpacket
            CharDataVector key_flags_data = {0x3, 0x0, 0x0, 0x0};
            signature_packet_ptr->AddSubpacketData(SST_KEY_FLAGS, key_flags_data, true);
            
            ///Preferred compress algorithms subpacket
            CharDataVector prefered_compress_algos = {0x3, 0x2, 0x1, 0x0};
            signature_packet_ptr->AddSubpacketData(SST_PREFERRED_COMPRESSION_ALGO, prefered_compress_algos, true);
            
            //Features subpacket
            CharDataVector features_data = {0x1, 0x0, 0x0, 0x0};
            signature_packet_ptr->AddSubpacketData(SST_FEATURES, features_data, true);
            
            ///Preferred hash algorithms subpacket
            CharDataVector prefered_hash_algos = {0x8, 0x9, 0xa};
            signature_packet_ptr->AddSubpacketData(SST_PREFERRED_HASH_ALGO, prefered_hash_algos, true);

            
            CharDataVector data_for_sign;
            if (GetDataForKeySignature(signature_packet_ptr, secret_key_packet_ptr->GetPublicKeyPatr(), user_id_packet_ptr, data_for_sign))
            {
                CharDataVector hash;
                CharDataVector digest_start;
                if (crypto::CalculateDigest(data_for_sign, signature_packet_ptr, hash, digest_start))
                {
                    std::vector<int> temp = {digest_start[0], digest_start[1]};
                    signature_packet_ptr->SetDigestStart(temp);
                    
                    PublicKeyAlgorithmPtr pub_key_algo_impl = GetPublicKeyAlgorithm(signature_packet_ptr->GetPublicKeyAlgorithm());
                    CharDataVector crypto_result;
                    
                    pub_key_algo_impl->EncryptWithPrivateKey(temp_secret_key, hash, crypto_result);
                    key_for_self_signature.reset(new SecretKeyPacket(*temp_secret_key));
                    
                    signature_packet_ptr->AddMPI(crypto_result);
                    public_key_message->AddPacket(signature_packet_ptr);
                }
            }
        }
        
        /// SUBKEY
        
        SecretKeyPacketPtr secret_subkey_packet_ptr = GenerateSecretKeyPacket(pub_key_algo, passphrase, num_bits, true);
        if (secret_subkey_packet_ptr == nullptr)
        {
            return nullptr;
        }

        secret_key_message->AddPacket(secret_subkey_packet_ptr);
        public_key_message->AddPacket(secret_subkey_packet_ptr->GetPublicKeyPatr());
        
        { // TODO extract to method
            
            SecretKeyPacketPtr temp_secret_key(new SecretKeyPacket(*secret_key_packet_ptr));
            if (!crypto::DecryptSecretKeyPacketData(temp_secret_key, passphrase))
            {
                if (!passphrase.empty())
                {
                    return nullptr;
                }
                
                ReloadMPIs(temp_secret_key);
            }
            
            SignaturePacketPtr signature_packet_ptr(new SignaturePacket(4));
            signature_packet_ptr->SetCreationTime(static_cast<int>(time(NULL)));
            signature_packet_ptr->SetHashAlgorithm(HA_SHA256);
            signature_packet_ptr->SetPublicKeyAlgorithm(PKA_RSA);
            KeyIDData key_id = key_for_self_signature->GetKeyID();
            signature_packet_ptr->SetKeyID(key_id);
            signature_packet_ptr->SetSignatureType(24);
            
            //Key flags subpacket
            CharDataVector key_flags_data = {0xc, 0x0, 0x0, 0x0};
            signature_packet_ptr->AddSubpacketData(SST_KEY_FLAGS, key_flags_data, true);

            
            {
                SignaturePacketPtr embedded_signature_packet_ptr(new SignaturePacket(4));
                embedded_signature_packet_ptr->SetCreationTime(static_cast<int>(time(NULL)));
                embedded_signature_packet_ptr->SetHashAlgorithm(HA_SHA256);
                embedded_signature_packet_ptr->SetPublicKeyAlgorithm(PKA_RSA);
                KeyIDData key_id = temp_secret_key->GetKeyID();
                embedded_signature_packet_ptr->SetKeyID(key_id);
                embedded_signature_packet_ptr->SetSignatureType(25);
                
                CharDataVector data_for_signature;
                if (GetDataForKeySignature(embedded_signature_packet_ptr, secret_key_packet_ptr->GetPublicKeyPatr(), secret_subkey_packet_ptr->GetPublicKeyPatr(), data_for_signature))
                {
                    CharDataVector hash;
                    CharDataVector digest_start;
                    if (crypto::CalculateDigest(data_for_signature, embedded_signature_packet_ptr, hash, digest_start))
                    {
                        std::vector<int> temp = {digest_start[0], digest_start[1]};
                        embedded_signature_packet_ptr->SetDigestStart(temp);
                        
                        PublicKeyAlgorithmPtr pub_key_algo_impl = GetPublicKeyAlgorithm(embedded_signature_packet_ptr->GetPublicKeyAlgorithm());
                        CharDataVector crypto_result;
                        
                        pub_key_algo_impl->EncryptWithPrivateKey(temp_secret_key, hash, crypto_result);
                        if (crypto_result.empty())
                        {
                            return nullptr;
                        }
                        embedded_signature_packet_ptr->AddMPI(crypto_result);
                        
                        CharDataVector embeded_packet_data;
                        embedded_signature_packet_ptr->GetBinaryData(embeded_packet_data);
                        
                        signature_packet_ptr->AddSubpacketData(SST_EMBEDDED_SIGNATURE, embeded_packet_data, true);
                    }
                }
            }
            
            CharDataVector data_for_sign;
            if (GetDataForKeySignature(signature_packet_ptr, secret_key_packet_ptr->GetPublicKeyPatr(), secret_subkey_packet_ptr->GetPublicKeyPatr(), data_for_sign))
            {
                CharDataVector hash;
                CharDataVector digest_start;
                if (crypto::CalculateDigest(data_for_sign, signature_packet_ptr, hash, digest_start))
                {
                    std::vector<int> temp = {digest_start[0], digest_start[1]};
                    signature_packet_ptr->SetDigestStart(temp);
                    
                    PublicKeyAlgorithmPtr pub_key_algo_impl = GetPublicKeyAlgorithm(signature_packet_ptr->GetPublicKeyAlgorithm());
                    CharDataVector crypto_result;
                    
                    pub_key_algo_impl->EncryptWithPrivateKey(key_for_self_signature, hash, crypto_result);
                    if (crypto_result.empty())
                    {
                        return nullptr;
                    }
                    signature_packet_ptr->AddMPI(crypto_result);
                    
                    public_key_message->AddPacket(signature_packet_ptr);
                }
            }

        }
        
        TransferingKeysPtr transfering_keys_ptr(new TransferingKeys);
        transfering_keys_ptr->private_key = secret_key_message;
        transfering_keys_ptr->public_key = public_key_message;
        
        return transfering_keys_ptr;
    }
    
    void GenerateSessionKey(int key_length, CharDataVector& session_key, int algo)
    {
        session_key.empty();
        
        if (algo == SKA_TRIPLE_DES)
        {
            for (int i = 0; i < 3; ++i)
            {
                DES_cblock des_key_block = {0};
                if (DES_random_key(&des_key_block) == 0)
                {
                    session_key.empty();
                    return;
                }
                
                DES_set_odd_parity(&des_key_block);
                CharDataVector temp_key = {des_key_block[0], des_key_block[1], des_key_block[2], des_key_block[3], des_key_block[4], des_key_block[5], des_key_block[6], des_key_block[7]};
                session_key.insert(session_key.end(), temp_key.begin(), temp_key.end());
            }
            
            return;
        }
        
        session_key.resize(key_length);
        
        if (!RAND_pseudo_bytes(&session_key[0], key_length))
        {
            session_key.clear();
            return;
        }

        return;
    }
}
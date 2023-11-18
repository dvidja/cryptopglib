//
//  PGPKeyData.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 16.5.14.
//  Copyright (c) 2014 Anton Sarychev. All rights reserved.
//

#include "pgp_key_data.h"
#include "../crypto/key_generator.h"

namespace
{
    size_t GetMPIDataLength(DataBuffer& data_buffer)
    {
        int l = data_buffer.GetNextTwoOctets();
        l = (l + 7) / 8;
        
        return l;
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
                                        passphrase.begin() + j - salt.size());
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
    
    void GetMPIsDataVector(SecretKeyPacketPtr secret_key, CharDataVector& result_data)
    {
        result_data.clear();
        
        switch (secret_key->GetPublicKeyPatr()->GetPublicKeyAlgorithm())
        {
            case PKA_RSA:
            case PKA_RSA_SIGN_ONLY:
            case PKA_RSA_ENCRYPT_ONLY:
                {
                    for (int i = 0; i < 4; ++i)
                    {
                        CharDataVector mpi = secret_key->GetMPI(i);
                        size_t mpi_size = mpi.size();
                        mpi_size *= 8;
                        
                        double t = mpi[0];
                        int bits = packet_helper::log2(t) + 1;
                        int delta = 8 - bits;
                        mpi_size -= delta;
                        
                        result_data.push_back((mpi_size >> 8) & 0xFF);
                        result_data.push_back(mpi_size & 0xFF);
                        result_data.insert(result_data.end(), mpi.begin(), mpi.end());
                    }
                    
                    return;
                }
                break;
                
            case PKA_ELGAMAL:
            case PKA_DSA:
                {
                    for (int i = 0; i < 1; ++i)
                    {
                        CharDataVector mpi = secret_key->GetMPI(i);
                        size_t mpi_size = mpi.size();
                        mpi_size *= 8;
                        
                        double t = mpi[0];
                        int bits = packet_helper::log2(t) + 1;
                        int delta = 8 - bits;
                        mpi_size -= delta;
                        
                        result_data.push_back((mpi_size >> 8) & 0xFF);
                        result_data.push_back(mpi_size & 0xFF);
                        result_data.insert(result_data.end(), mpi.begin(), mpi.end());
                    }
                    
                    return;
                }
                break;
            default:
                break;
        }
    }
}

namespace crypto
{
    bool PGPKeyDataEncrypt(PGPMessagePtr private_key, const std::string& passphrase)
    {
        if (private_key->GetMessageType() != PGPMessageType::MT_PRIVATE_KEY)
        {
            // TODO: handle error data is not private key
            return false;
        }
        
        PGPPacketsArray packets = private_key->GetPackets();
        for (auto iter = packets.begin(); iter != packets.end(); ++iter)
        {
            if (((*iter)->GetPacketType() == PT_SECRET_KEY_PACKET) || ((*iter)->GetPacketType() == PT_SECRET_SUBKEY_PACKET))
            {
                SecretKeyPacketPtr key_packet = std::dynamic_pointer_cast<SecretKeyPacket>((*iter));
                bool result = EncryptSecretKeyPacketData(key_packet, passphrase);
                if (!result)
                {
                    //TODO: handle error  Can't decrypt private key data
                    return false;
                }
            }
        }


        return true;
    }
    
    bool PGPKeyDataDecrypt(PGPMessagePtr private_key, const std::string& passphrase)
    {
        if (private_key->GetMessageType() != PGPMessageType::MT_PRIVATE_KEY)
        {
            // TODO: handle error data is not private key
            return false;
        }
        
        if (PGPGKeyIsEncrypted(private_key))
        {
            PGPPacketsArray packets = private_key->GetPackets();
            for (auto iter = packets.begin(); iter != packets.end(); ++iter)
            {
                if (((*iter)->GetPacketType() == PT_SECRET_KEY_PACKET) || ((*iter)->GetPacketType() == PT_SECRET_SUBKEY_PACKET))
                {
                    SecretKeyPacketPtr key_packet = std::dynamic_pointer_cast<SecretKeyPacket>((*iter));
                    bool result = DecryptSecretKeyPacketData(key_packet, passphrase);
                    if (!result)
                    {
                        //TODO: handle error  Can't decrypt private key data
                        return false;
                    }
                }
            }
        }
     
        return true;
    }
    
    bool PGPGKeyIsEncrypted(PGPMessagePtr private_key)
    {
        if (private_key->GetMessageType() != PGPMessageType::MT_PRIVATE_KEY)
        {
            // TODO: handle error data is not private key
            return false;
        }
        
        PGPPacketsArray packets = private_key->GetPackets();
        for (auto iter = packets.begin(); iter != packets.end(); ++iter)
        {
            if (((*iter)->GetPacketType() == PT_SECRET_KEY_PACKET) || ((*iter)->GetPacketType() == PT_SECRET_SUBKEY_PACKET))
            {
                SecretKeyPacketPtr key_packet = std::dynamic_pointer_cast<SecretKeyPacket>((*iter));
                
                if (key_packet->GetStringToKeyUsage() != 0) //private key data is encrypted
                {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    bool DecryptSecretKeyPacketData(SecretKeyPacketPtr secret_key, const std::string& passphrase)
    {
        crypto::HashAlgorithmPtr hash_impl = crypto::GetHashImpl(secret_key->GetStringToKeyHashAlgorithm());
        crypto::SymmetricKeyAlgorithmPtr sym_key_algo_impl = crypto::GetSymmetricKeyAlgorithm(secret_key->GetSymmetricKeyAlgorithm());
        if (!hash_impl && !sym_key_algo_impl)
        {
            return false;
        }
        
        std::vector<CharDataVector> hashes;
        std::vector<crypto::HashAlgorithmPtr> hashes_impl;
        for(int n = 0 ;  n * hash_impl->GetDigestLength() < sym_key_algo_impl->GetKeyLength(); ++n)
	    {
            hashes.push_back(CharDataVector());
            hashes_impl.push_back(crypto::GetHashImpl(secret_key->GetStringToKeyHashAlgorithm()));
            hashes_impl[n]->Init();
            for(int i = 0 ; i < n ; ++i)
            {
                hashes[n].push_back(0);
                CharDataVector dat = {0};
                hashes_impl[n]->Update(dat);
            }
	    }
        
        int count1 = secret_key->GetCount();
        
        for(int n = 0 ; n * hash_impl->GetDigestLength() < sym_key_algo_impl->GetKeyLength(); ++n)
	    {
            switch(secret_key->GetStringToKeySpecifier())
            {
                case 1:
                {
                    CharDataVector data(secret_key->GetSaltValue().begin(), secret_key->GetSaltValue().end());
                    hashes_impl[n]->Update(data);
                }
                    // flow through...
                case 0:
                {
                    CharDataVector data(passphrase.begin(), passphrase.end());
                    hashes_impl[n]->Update(data);
                }
                    
                    break;
                    
                case 3:
					int sgc = secret_key->GetCount();
					int a = passphrase.size() + secret_key->GetSaltValue().size();
                    for(int i = 0 ; i < secret_key->GetCount() ; i += passphrase.size() + secret_key->GetSaltValue().size())
                    {
                        int j = static_cast<int>(passphrase.size()) + static_cast<int>(secret_key->GetSaltValue().size());
                        
                        if(i + j > secret_key->GetCount() && i != 0)
                        {
                            j = secret_key->GetCount() - i;
                        }
                        
                        CharDataVector data(secret_key->GetSaltValue().begin(),
                                            secret_key->GetSaltValue().begin() + (j > secret_key->GetSaltValue().size() ? secret_key->GetSaltValue().size() : j));
                        
                        hashes_impl[n]->Update(data);
                        
                        if (j > secret_key->GetSaltValue().size())
                        {
							
                            CharDataVector data(passphrase.begin(),
                                                passphrase.begin() + (j - secret_key->GetSaltValue().size()));
                            hashes_impl[n]->Update(data);
                            
                        }
                    }
                    
                    break;
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
        
        CharDataVector result_data;
        
        if (secret_key->GetPublicKeyPatr()->GetKeyVersion() == 4) // check key version
        {
            sym_key_algo_impl->DecryptInCFBMode(secret_key->GetMPI(0), session_key, secret_key->GetInitialVector(), result_data);
            if (result_data.empty())
            {
                // TODO : handle error Decrypt error
                return false;
            }
            
            DataBuffer data_buffer(result_data);
            secret_key->ClearMPIData();
            switch (secret_key->GetPublicKeyPatr()->GetPublicKeyAlgorithm())
            {
                case PKA_RSA:
                case PKA_RSA_ENCRYPT_ONLY:
                case PKA_RSA_SIGN_ONLY:
                {
                    size_t length = GetMPIDataLength(data_buffer);
                    secret_key->AddMPI(data_buffer.GetRange(length));
                    
                    length = GetMPIDataLength(data_buffer);
                    secret_key->AddMPI(data_buffer.GetRange(length));
                    
                    length = GetMPIDataLength(data_buffer);
                    secret_key->AddMPI(data_buffer.GetRange(length));
                    
                    length = GetMPIDataLength(data_buffer);
                    secret_key->AddMPI(data_buffer.GetRange(length));
                }
                    break;
                case PKA_ELGAMAL:
                case PKA_DSA:
                {
                    size_t length = GetMPIDataLength(data_buffer);
                    secret_key->AddMPI(data_buffer.GetRange(length));
                }
                    break;
                    
                default:
                    return false;
            }
            
            if (secret_key->GetStringToKeyUsage() == 254)
            {
                CharDataVector sha_hash = data_buffer.GetRange(20);
                
                CharDataVector hash_result;
                crypto::Sha1 sha1;
                CharDataVector source(result_data.begin(), result_data.end() - 20);
                sha1.Hash(source, hash_result);
                if (hash_result.size() != sha_hash.size())
                {
                    return false;
                }
                
                if (!std::equal(sha_hash.begin(), sha_hash.end(), hash_result.begin()))
                {
                    return false;
                }
                
            }
            else
            {
                CharDataVector checksum = data_buffer.GetRange(2);
            }
        }
        
        return  true;
    }
    
    bool EncryptSecretKeyPacketData(SecretKeyPacketPtr secret_key, const std::string& passphrase)
    {
        CharDataVector salt;
        crypto::GenerateSessionKey(8, salt, -1);
        secret_key->SetSaltValue(salt); // 8 bytes
        
        crypto::SymmetricKeyAlgorithmPtr sym_key_algo_impl = crypto::GetSymmetricKeyAlgorithm(secret_key->GetSymmetricKeyAlgorithm());
        CharDataVector initial_vector;
        crypto::GenerateSessionKey(sym_key_algo_impl->GetCipherBlockSize(), initial_vector, -1);
        secret_key->SetInitialVector(initial_vector);
        
        CharDataVector mpis_data_vector;
        GetMPIsDataVector(secret_key, mpis_data_vector);
        
        //GetMPIsDataVector(secret_key, mpis_data_vector);
        
        crypto::HashAlgorithmPtr hash_algo_impl = crypto::GetHashImpl(HA_SHA1);
        CharDataVector hash_checksum;
        hash_algo_impl->Hash(mpis_data_vector, hash_checksum);
        mpis_data_vector.insert(mpis_data_vector.end(), hash_checksum.begin(), hash_checksum.end());
        
        CharDataVector encoded_data;
        EncryptData(mpis_data_vector, passphrase, salt, initial_vector, secret_key->GetCount(), encoded_data);
        //secret_key_packet_ptr->AddMPI(encoded_data); // encoded mpis        
        
        secret_key->ClearMPIData();
        secret_key->AddMPI(encoded_data);

        return true;

    }
}



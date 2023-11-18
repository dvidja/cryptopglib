//
//  OpenPGPImpl.h
//  cryptopg
//
//  Created by Anton Sarychev on 19.6.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#pragma once

#include <iostream>
#include <vector>
#include "cryptopglib/pgp_message_type.h"
#include "openpgp_info_getter.h"
#include "crypto/pgp_signature.h"
#include "crypto/pgpg_decrypt.h"



class KeyInfoImpl
{
public:
    KeyInfoImpl()
        : expired_key_time_(0)
    {
    }
    
    typedef KeyIDData KeyIdType;
    
    KeyIdType public_key_id_;
    std::string key_fingerprint_;
    std::vector<std::string> users_id_;
    std::vector<KeyIdType> public_sub_keys_id_;
    std::vector<std::string> sub_key_fingerprint_;
    std::vector<SignatureKeyInfo> signature_keys_info_;
    
    PublicKeyAlgorithms key_type_;
    std::string size_;
    unsigned int created_time_;
    unsigned int  expired_key_time_;
    std::vector<HashAlgorithms> prefered_hash_algorithms_;
    std::vector<SymmetricKeyAlgorithms> prefered_chipers_;
    std::vector<CompressionAlgorithms> prefered_compression_algorithms_;
};

struct KeyPairImpl
{
    std::string public_key;
    std::string secret_key;
};



class OpenPGPImpl
{
public:
    explicit OpenPGPImpl(OpenPGPInfoGetter* pgp_info_getter);
    ~OpenPGPImpl();
    
    KeyInfoImpl GetKeyInfo(const std::string& message);
    PGPMessageType GetMessageType(const std::string& message);
    
    SignatureKeyInfo ReadSignatureMessage(const std::string& signature);
    
    SignatureResultInfo CheckSignature(const std::string& message, const std::string& public_key);
    SignatureResultInfo CheckSignature(const std::string& signature, const std::string& plain_text, const std::string& public_key);
    std::string SignMessage(const std::string& message, const std::string& key, const std::string& passhprase, const int hash_algo, bool armored = false);
        
    void GetSecretKeyIDForCryptoMessage(const std::string& message, std::vector<KeyIDData>& key_ids);
    bool IsSecretKeyEncrypted(const std::string& message);
    
    DecodedDataInfoPtr DecryptMessage(const std::string& message, const std::string& secret_key, const std::string& passphrase);
    DecodedDataInfoPtr DecryptMessage(const std::string& message, std::vector<CharDataVector> attached_data, const std::string& secret_key, const std::string& passphrase);
    SignatureResultInfo CheckSignatureForDecryptedData(const CharDataVector& data, const std::string& signature, const std::string& public_key);
    
    std::string EncryptData(const std::string& plain_text, const std::vector<std::string>& addressers_public_keys, const std::string& own_public_key);
    
    KeyPairImpl GenerateKeyPair(const std::string& email, const std::string& passphrase);
    
    std::string EncryptAndSignMessage(const std::string& message, const std::vector<std::string>& encrypt_keys, const std::string& sign_key, const std::string& passphrase);
    
    bool IsPassphraseCorrect(const std::string& secret_key, const std::string& passphrase);
    
    CheckSignatureResult CheckKeySignature(const std::string& signed_key, const std::string& verification_key);
    std::string SignPublicKey(const std::string& public_key, const std::string& private_key, const std::string& passphrase);
    
    std::string ChangePassphrase(const std::string& private_key, const std::string& old_passwd, const std::string& new_passwd);
    
private:
    OpenPGPInfoGetterPtr pgp_info_getter_;
};


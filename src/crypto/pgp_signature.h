//
//  PGPSignature.h
//  cryptopg
//
//  Created by Anton Sarychev on 14.6.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_PGPSignature_h
#define cryptopg_PGPSignature_h

#include "../pgp_message_impl.h"

#include "hash_algorithms.h"
#include "public_key_algorithms.h"
#include "../pgp_data/packets/signature_packet.h"
#include "../openpgp_info_getter.h"
#include "../pgp_data/packets/secret_key_packet.h"


typedef enum
{
    SR_NONE_SIGNATURE = 0,
    SR_SIGNATURE_VERIFIED,
    SR_SIGNATURE_FAILURE,
    SR_KEY_NOT_FOUND
} CheckSignatureResult;

struct SignatureResultInfo
{
public:
    SignatureResultInfo()
        : create_signature_time_(0)
        , expired_signature_time_(0)
    {
    }
    CheckSignatureResult signature_result_;
    unsigned int create_signature_time_;
    unsigned int expired_signature_time_;
};

class SignatureKeyInfo
{
public:
    KeyIDData keyID;
    unsigned int createdTime;
    unsigned int expirationTime;
};

namespace crypto
{
    SignatureKeyInfo GetSignatureKeyID(PGPMessagePtr message_ptr);
    
    SignatureResultInfo CheckSignature(PGPMessagePtr message_ptr, const std::string& public_key);
    CheckSignatureResult CheckSignature(CharDataVector data, SignaturePacketPtr signature_packet, const std::string& public_key);
    
    CheckSignatureResult CheckKeySignature(const std::string& signed_key, const std::string& verification_key);
    
    PGPMessagePtr SignMessage(const std::string& message,
                              PGPMessagePtr private_key,
                              HashAlgorithms hash_algo);
    
    
    SignaturePacketPtr SignRawData(const CharDataVector& data, SecretKeyPacketPtr secret_key, HashAlgorithms hash_algo);
    
    void GetDigestData(SignaturePacketPtr signature_packet_ptr, PublicKeyPacketPtr public_key_packet_ptr, CharDataVector& digest_data);
    
    bool CalculateDigest(const CharDataVector& data, SignaturePacketPtr signature_packet_ptr, CharDataVector& hash, CharDataVector& digest_start);
    
    PGPMessagePtr SignPublicKey(PGPMessagePtr public_key,
                              PGPMessagePtr private_key);
}

#endif
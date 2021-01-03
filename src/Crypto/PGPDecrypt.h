//
//  PGPDecrypt.h
//  cryptopg
//
//  Created by Anton Sarychev on 4.8.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__PGPDecrypt__
#define __cryptopg__PGPDecrypt__

#include <string>
#include "../PGPMessageImpl.h"
#include "PublicKeyAlgorithms.h"

#include "../PGPData/Packets/SecretKeyPacket.h"
#include "../PGPData/Packets/PublicKeyEncryptedPacket.h"
#include "../PGPData/Packets/SymmetricallyEncryptedDataPacket.h"
#include "../PGPData/Packets/CompressedDataPacket.h"
#include "../PGPData/Packets/LiteralDataPacket.h"
#include "../PGPData/Packets/SignaturePacket.h"
#include "../PGPData/Packets/ModificationDetectionCodePacket.h"

#include "../IOpenPGPInfoGetter.h"
#include "PGPSignature.h"

struct DecodedDataInfo;

typedef std::shared_ptr<DecodedDataInfo> DecodedDataInfoPtr;

struct DecodedDataInfo
{
public:
    typedef enum
    {
        DDI_NONE_SIGNATURE = 0,
        DDI_SIGNATURE_VERIFIED,
        DDI_SIGNATURE_FAILURE,
        DDI_KEY_NOT_FOUND
    } SignatureState;
    
    DecodedDataInfo()
        : decoded_data_(CharDataVector())
        , is_signed_(false)
    {
    }
    
    CharDataVector decoded_data_;
    CharDataVector file_name_;
    bool is_signed_;
    
    std::vector<DecodedDataInfoPtr> attached_data_;
    
    SignatureKeyInfo signatureKeyInfo;
    std::string signature_data;
};


namespace crypto
{
    bool DecryptSessionKey(PublicKeyEncryptedPacketPtr pub_key_enc, SecretKeyPacketPtr secret_key, CharDataVector& decrypt_data, const std::string& passphrase);
    
    class PGPDecrypt
    {
    public:
        PGPDecrypt(IOpenPGPInfoGetterPtr pgp_info_getter);
        
        void GetSecretKeyID(PGPMessagePtr crypt_msg, std::vector<KeyIDData>& key_id);
        bool IsSecretKeyEncoded(PGPMessagePtr sec_key_ptr);
        DecodedDataInfoPtr DecryptMessage(PGPMessagePtr crypt_msg, PGPMessagePtr sec_key_ptr, const std::string& passphrase);
        
    private:
        void SymmetricKeyDecrypt(CharDataVector& session_key_data, const CharDataVector& encrypted_data, bool flag);
        void HandlePacket(CompressedDataPacketPtr compression_packet);
        bool HandleDecryptedData(const CharDataVector& decrypted_data, const int shift);
        void CheckSignature(SignaturePacketPtr signature_packet_ptr);
        
    private:
        IOpenPGPInfoGetterPtr pgp_info_getter_;
        DecodedDataInfoPtr decoded_data_info_;
        
    };
}

#endif /* defined(__cryptopg__PGPDecrypt__) */

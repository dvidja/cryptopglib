//
//  PGPKeyData.h
//  cryptopg
//
//  Created by Anton Sarychev on 16.5.14.
//  Copyright (c) 2014 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_PGPKeyData_h
#define cryptopg_PGPKeyData_h

#include "../PGPMessageImpl.h"
#include "../PGPData/Packets/SecretKeyPacket.h"

namespace  crypto
{
    bool PGPKeyDataEncrypt(PGPMessagePtr private_key, const std::string& passphrase);
    bool PGPKeyDataDecrypt(PGPMessagePtr private_key, const std::string& passphrase);
    bool PGPGKeyIsEncrypted(PGPMessagePtr private_key);
    
    bool DecryptSecretKeyPacketData(SecretKeyPacketPtr secret_key, const std::string& passphrase);
    bool EncryptSecretKeyPacketData(SecretKeyPacketPtr secret_key, const std::string& passphrase);
}

#endif

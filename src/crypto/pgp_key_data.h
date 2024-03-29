//
//  PGPKeyData.h
//  cryptopg
//
//  Created by Anton Sarychev on 16.5.14.
//  Copyright (c) 2014 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_PGPKeyData_h
#define cryptopg_PGPKeyData_h

#include "../pgp_message_impl.h"
#include "../pgp_data/packets/secret_key_packet.h"

namespace  cryptopglib::crypto
{
    using pgp_data::packets::SecretKeyPacketPtr;

    bool PGPKeyDataEncrypt(PGPMessagePtr private_key, const std::string& passphrase);
    bool PGPKeyDataDecrypt(PGPMessagePtr private_key, const std::string& passphrase);
    bool PGPGKeyIsEncrypted(PGPMessagePtr private_key);
    
    bool DecryptSecretKeyPacketData(SecretKeyPacketPtr secret_key, const std::string& passphrase);
    bool EncryptSecretKeyPacketData(SecretKeyPacketPtr secret_key, const std::string& passphrase);
}

#endif

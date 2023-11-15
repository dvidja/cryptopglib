//
//  KeyGenerator.h
//  cryptopg
//
//  Created by Anton Sarychev on 9.7.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__KeyGenerator__
#define __cryptopg__KeyGenerator__

#include "public_key_algorithms.h"
#include "../pgp_message_impl.h"

namespace crypto
{
    struct TransferingKeys
    {
        PGPMessagePtr public_key;
        PGPMessagePtr private_key;
    };
    
    typedef std::shared_ptr<TransferingKeys> TransferingKeysPtr;
    
    TransferingKeysPtr GenerateSecretKey(const std::string& user_email, const std::string& passphrase, PublicKeyAlgorithms pub_key_algo, const int num_bits);
    
    void GenerateSessionKey(int key_length, CharDataVector& session_key, int algo);
}

#endif /* defined(__cryptopg__KeyGenerator__) */

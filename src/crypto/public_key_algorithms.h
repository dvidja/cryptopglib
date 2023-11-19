//
//  PublicKeyAlgorithms.h
//  cryptopg
//
//  Created by Anton Sarychev on 13.6.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_PublicKeyAlgorithms_h
#define cryptopg_PublicKeyAlgorithms_h

namespace cryptopglib {
    enum PublicKeyAlgorithms {
        PKA_RSA = 1,
        PKA_RSA_ENCRYPT_ONLY = 2,
        PKA_RSA_SIGN_ONLY = 3,
        PKA_ELGAMAL = 16,
        PKA_DSA = 17,
    };
}
#endif

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
        kRSA = 1,
        kRSAEncryptOnly = 2,
        kRSASignOnly = 3,
        kElgamal = 16,
        kDSA = 17,
    };
}
#endif

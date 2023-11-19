//
// Created by Anton Sarychev on 19.11.23.
//

#pragma once

namespace cryptopglib {
    enum PublicKeyAlgorithms
    {
        PKA_RSA = 1,
        PKA_RSA_ENCRYPT_ONLY = 2,
        PKA_RSA_SIGN_ONLY = 3,
        PKA_ELGAMAL = 16,
        PKA_DSA = 17,
    };
}

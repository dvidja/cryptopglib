//
// Created by Anton Sarychev on 19.11.23.
//

#pragma once

namespace cryptopglib {
    enum class PublicKeyAlgorithms
    {
        kRSA = 1,
        kRSAEncryptOnly = 2,
        kRSASignOnly = 3,
        kElgamal = 16,
        kDSA = 17,
    };
}

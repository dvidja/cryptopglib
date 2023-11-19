//
// Created by Anton Sarychev on 19.11.23.
//

#pragma once

namespace cryptopglib {
    enum class SymmetricKeyAlgorithms {
        kPlainText = 0,
        kIdea = 1,
        tTripleDES = 2,
        kCast5 = 3,
        kBlowfish = 4,

        kAES128 = 7,
        kAES192 = 8,
        kAES256 = 9,
        kTwofish = 10, /// ???
    };
}

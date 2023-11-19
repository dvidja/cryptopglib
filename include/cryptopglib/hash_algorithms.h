//
// Created by Anton Sarychev on 19.11.23.
//

#pragma once

namespace cryptopglib {
    enum class HashAlgorithms {
        kNoHash = 0,
        kMD5 = 1,
        kSHA1 = 2,
        kRipeMD = 3,

        kSHA256 = 8,
        kSHA384 = 9,
        kSHA512 = 10,
        kSHA224 = 11,
    };
}

//
// Created by Anton Sarychev on 19.11.23.
//

#pragma once

namespace cryptopglib {
    enum HashAlgorithms {
        HA_NO_HASH = 0,
        HA_MD5 = 1,
        HA_SHA1 = 2,
        HA_RIPE_MD = 3,

        HA_SHA256 = 8,
        HA_SHA384 = 9,
        HA_SHA512 = 10,
        HA_SHA224 = 11,
    };
}

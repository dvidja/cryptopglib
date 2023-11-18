//
// Created by Anton Sarychev on 18.11.23.
//

#pragma once

#include <string>

namespace cryptopglib
{
    struct PGPKeyInfo {
        std::string key_fingerprint;
        std::vector<std::string> users_id;
    };
}


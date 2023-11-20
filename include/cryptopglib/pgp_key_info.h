//
// Created by Anton Sarychev on 18.11.23.
//
#ifndef CRYPTOPGLIB_PGP_KEY_INFO
#define CRYPTOPGLIB_PGP_KEY_INFO

#include <iostream>
#include <string>

namespace cryptopglib
{
    struct PGPKeyInfo {
        std::string key_fingerprint;
        std::vector<std::string> users_id;

        friend std::ostream& operator<<(std::ostream& stream, const PGPKeyInfo& pgp_key_info);
    };
}

#endif //CRYPTOPGLIB_PGP_KEY_INFO


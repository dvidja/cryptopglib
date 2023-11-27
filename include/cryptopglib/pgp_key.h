//
// Created by Anton Sarychev on 18.11.23.
//
#pragma once

#include <iostream>
#include <string>


namespace cryptopglib
{
    class PGPKey {
    public:
        std::string key_fingerprint;
        std::vector<std::string> users_id;
        bool is_secret_key;
        bool is_encrypted;

        friend std::ostream& operator<<(std::ostream& stream, const PGPKey& pgp_key_info);
    };
}



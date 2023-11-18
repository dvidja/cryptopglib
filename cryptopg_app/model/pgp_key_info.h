//
// Created by Anton Sarychev on 18.11.23.
//

#ifndef CRYPTOPGAPP_PGP_KEY_INFO_H
#define CRYPTOPGAPP_PGP_KEY_INFO_H

#include <filesystem>

struct PGPKeyInfo {
    std::string key_fingerprint;
    std::vector<std::string> users_id;
};

void PrintKeyInfo(const std::filesystem::path& file_path);


#endif //CRYPTOPGAPP_PGP_KEY_INFO_H

//
// Created by Anton Sarychev on 18.11.23.
//

#include "pgp_key_info.h"

#include "utils.h"
#include "cryptopglib/cryptopg.h"


void PrintKeyInfo(const std::filesystem::path& file_path) {
    if (!std::filesystem::exists(file_path) ) {
        std::cerr << "Error: File: " << file_path << " is not exist." << std::endl;
        return;
    }

    std::string file_data = utils::ReadFileData(file_path);
    auto pgp_key_info = cryptopglib::GetPPGKeyInfo(file_data);


    std::cout << "From Prog: " << std::endl;
    std::cout << pgp_key_info.key_fingerprint << std::endl;
    for (const auto& user : pgp_key_info.users_id) {
        std::cout << user;
    }

    std::cout << "From Lib: " << std::endl;
    std::cout << pgp_key_info;
}
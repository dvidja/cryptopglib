//
// Created by Anton Sarychev on 18.11.23.
//

#include "pgp_key_info.h"

#include <iostream>

#include "utils.h"


void GetKeyInfo(const std::filesystem::path& file_path) {
    if (!std::filesystem::exists(file_path) ) {
        std::cerr << "Error: File: " << file_path << " is not exist." << std::endl;
        return;
    }

    auto file_data = utils::ReadFileData(file_path);


}
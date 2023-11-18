//
// Created by Anton Sarychev on 18.11.23.
//

#ifndef CRYPTOPGAPP_UTILS_H
#define CRYPTOPGAPP_UTILS_H

#include <string>
#include <filesystem>

namespace utils {
    std::string ReadFileData(const std::filesystem::path& file_path);
}



#endif //CRYPTOPGAPP_UTILS_H

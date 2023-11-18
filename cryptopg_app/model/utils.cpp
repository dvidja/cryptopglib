//
// Created by Anton Sarychev on 18.11.23.
//

#include "utils.h"

#include <fstream>


namespace utils {
    std::string ReadFileData(const std::filesystem::path& file_path) {
        std::ifstream t(file_path);
        std::string result;

        t.seekg(0, std::ios::end);
        result.reserve(t.tellg());
        t.seekg(0, std::ios::beg);

        result.assign((std::istreambuf_iterator<char>(t)),
                   std::istreambuf_iterator<char>());

        return result;
    }
}
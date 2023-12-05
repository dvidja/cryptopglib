//
// Created by Anton Sarychev on 28.11.23.
//
#include <gtest/gtest.h>

#include <fstream>
#include <string>


#include "../include/cryptopglib/cryptopg.h"


std::string ReadFileData(std::string&& path) {
    std::ifstream file_stream(path);
    std::string result;

    file_stream.seekg(0, std::ios::end);
    result.reserve(file_stream.tellg());
    file_stream.seekg(0, std::ios::beg);

    result.assign((std::istreambuf_iterator<char>(file_stream)),
               std::istreambuf_iterator<char>());

    return result;
}

TEST(PGPMessageParserTests, ParsePublicKey)
{
    std::string pgp_message_data = ReadFileData("test_data/public_key.asc");

    auto message = cryptopglib::ReadPGPMessage(pgp_message_data);

    ASSERT_TRUE(true);
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
//
// Created by Anton Sarychev on 1/3/21.
//

#pragma once

#include <exception>
#include <string>


const std::string MESSAGE_CRC_ERROR = "Error CRC checksum in message";
const std::string PACKAGE_FIRST_BYTE_ERROR = "First bit is not 1";
const std::string PACKAGE_LENGTH_ERROR = "Unknown package length";
const std::string PACKAGE_UNKNOWN_TYPE = "Unknown package type";


class PGPError : public std::exception{
public:
    explicit PGPError (const std::string& what_arg);

    const char* what() const noexcept override;

    ~PGPError() override = default;
private:
    std::string what_;
};


//
// Created by Anton Sarychev on 1/3/21.
//

#ifndef CRYPTOPGLIB_PGPERRORS_H
#define CRYPTOPGLIB_PGPERRORS_H

#include <exception>
#include <string>


const char MESSAGE_CRC_ERROR[] = "Error CRC checksum in message";
const char PACKAGE_FIRST_BYTE_ERROR[] = "First bit is not 1";
const char PACKAGE_LENGTH_ERROR[] = "Unknown package length";
const char PACKAGE_UNKNOWN_TYPE[] = "Unknown package type";


class PGPError : public std::exception{
public:
    explicit PGPError (const std::string& what_arg);

    virtual const char* what() const throw() override;

    virtual ~PGPError() _NOEXCEPT override;
private:
    std::string what_;
};


#endif //CRYPTOPGLIB_PGPERRORS_H

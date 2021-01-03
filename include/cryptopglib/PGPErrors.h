//
// Created by Anton Sarychev on 1/3/21.
//

#ifndef CRYPTOPGLIB_PGPERRORS_H
#define CRYPTOPGLIB_PGPERRORS_H

#include <exception>
#include <string>

class PGPError : public std::exception{
public:
    explicit PGPError (const std::string& what_arg);

    virtual const char* what() const throw() override;

    virtual ~PGPError() _NOEXCEPT override;
private:
    std::string what_;
};


#endif //CRYPTOPGLIB_PGPERRORS_H

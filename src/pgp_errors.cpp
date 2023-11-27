//
// Created by Anton Sarychev on 1/3/21.
//

#include "cryptopglib/pgp_errors.h"


PGPError::PGPError(const std::string& what_arg)
{
    what_.assign(what_arg);
}

const char* PGPError::what() const throw()
{
    return what_.c_str();
}

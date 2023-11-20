#pragma once

#include <string>

#include "pgp_key_info.h"


namespace cryptopglib {

    PGPKeyInfo GetPPGKeyInfo(std::string&& pgp_key_data);

}
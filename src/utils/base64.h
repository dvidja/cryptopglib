//
//  base64.h
//  OpenPGPLib
//
//  Created by Anton Sarychev on 2.3.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#pragma once

#include <cstdlib>
#include <string>
#include <set>

#include "../pgp_data/pgp_data_types.h"


namespace cryptopglib::utils
{    
    std::string Base64Encode(CharDataVector inputBuffer);

    CharDataVector Base64Decode(const std::string& input);
}

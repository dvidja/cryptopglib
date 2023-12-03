//
//  crc24.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.3.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#pragma once

#include <cstdio>
#include "../pgp_data/pgp_data_types.h"

namespace cryptopglib::utils
{
    long CRC24(const std::vector<unsigned char>& data);
}


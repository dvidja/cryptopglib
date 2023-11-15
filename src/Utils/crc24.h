//
//  crc24.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.3.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#pragma once

#include <stdio.h>
#include "../PGPData/PGPDataTypes.h"

namespace Utils
{
    long CRC24(const CharDataVector& data);
}


//
//  crc24.c
//  cryptopg
//
//  Created by Anton Sarychev on 2.3.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "crc24.h"

#define CRC24_INIT 0xB704CE
#define CRC24_POLY 0x864CFB


namespace cryptopglib::utils
{
    long CRC24(const CharDataVector& data)
    {
        long crc = CRC24_INIT;
        size_t len = data.size();
        
        auto iter = data.begin();
        
        int i;
        while (len--)
        {
            crc ^= (*iter++) << 16;
            
            for (i = 0; i < 8; i++)
            {
                crc <<= 1;
                if (crc & 0x1000000)
                {
                    crc ^= CRC24_POLY;
                }
            }
        }
        
        return crc & 0xFFFFFF;
    }
}

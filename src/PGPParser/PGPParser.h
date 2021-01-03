//
//  PGPParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 22.4.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__PGPParser__
#define __cryptopg__PGPParser__

#include <iostream>
#include <memory>
#include "../PGPMessageImpl.h"

#include "PGPMessageParser.h"
#include "PGPPacketsParser.h"


class PGPParser
{
public:
    PGPParser();
    
    PGPMessagePtr ParseMessage(const std::string& message);
};

#endif /* defined(__cryptopg__PGPParser__) */

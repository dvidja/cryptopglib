//
//  PGPParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 22.4.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_PGPParser_
#define cryptopg_PGPParser_

#include <iostream>
#include <memory>
#include "../pgp_message_impl.h"

#include "pgp_message_parser.h"
#include "pgp_packets_parser.h"


class PGPParser
{
public:
    PGPParser();
    
    PGPMessagePtr ParseMessage(const std::string& message);
};

#endif /* cryptopg_PGPParser_ */

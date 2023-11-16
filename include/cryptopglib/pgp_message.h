//
//  PGPMessage.h
//  cryptopg
//
//  Created by Anton Sarychev on 16.3.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#pragma once

#include <iostream>
#include <map>


#include "pgp_message_type.h"


class PGPMessage
{
public:
    typedef std::map<std::string, std::string> ArmorHeadersMap;
    
public:
    virtual ~PGPMessage()= default;
    
    virtual PGPMessageType GetMessageType() = 0;
    virtual std::string GetPlainText() = 0;
    virtual std::string GetBase64Data() = 0;
    virtual std::string GetCRC() = 0;
};


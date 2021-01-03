//
//  PGPMessage.h
//  cryptopg
//
//  Created by Anton Sarychev on 16.3.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__PGPMessage__
#define __cryptopg__PGPMessage__

#include <iostream>
#include <map>


#include "PGPMessageType.h"


class PGPMessage
{
public:
    typedef std::map<std::string, std::string> ArmorHeadersMap;
    
public:
    virtual ~PGPMessage(){};
    
    virtual PGPMessageType GetMessageType() = 0;
    virtual std::string GetPlainText() = 0;
    virtual std::string GetBase64Data() = 0;
    virtual std::string GetCRC() = 0;
};

#endif /* defined(__cryptopg__PGPMessage__) */

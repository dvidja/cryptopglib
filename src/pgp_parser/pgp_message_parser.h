//
//  PGPMessageParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 16.3.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__PGPMessageParser__
#define __cryptopg__PGPMessageParser__

#include <iostream>
#include <map>
#include <memory>


#include "cryptopglib//pgp_message_type.h"
#include "../pgp_message_impl.h"



enum ParserState
{
    PS_START_LINE = 0,
    PS_SIGNED_TEXT,
    PS_ARMOR,
    PS_DATA,
    PS_END_LINE,
};


class PGPMessageParser
{
public:
    PGPMessageParser();
    ~PGPMessageParser();
    
    PGPMessagePtr ParseMessage(const std::string& source);

private:
    void ParseLine(const std::string& source);
    bool ParseArmorHeaderLine(const std::string& source);
    bool ParseArmorHeaders(const std::string& source);
    bool ReadSignedTextLine(const std::string& source);
    bool ReadDataLine(const std::string& source);
    
    void ParseHeaderWord(const std::string& word);
    
    bool CheckCRCSum();
    
    ParserState state_;
    
    //MessageInfo message_info_;
    PGPMessagePtr message_;
};

#endif /* defined(__cryptopg__PGPMessageParser__) */

//
//  PGPMessageParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 16.3.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_PGPMessageParser_
#define cryptopg_PGPMessageParser_

#include <iostream>
#include <map>
#include <memory>


#include "cryptopglib//pgp_message_type.h"
#include "../pgp_message_impl.h"


/// Here will be a new implementation of parsing the message
namespace cryptopglib::pgp_parser {


}



/// here old implementation


namespace cryptopglib::pgp_parser {
    enum ParserState {
        PS_START_LINE = 0,
        PS_SIGNED_TEXT,
        PS_ARMOR,
        PS_DATA,
        PS_END_LINE,
    };


    class PGPMessageParserOld {
    public:
        PGPMessagePtr ParseMessage(const std::string &source);

    private:
        void ParseLine(const std::string &source);

        bool ParseArmorHeaderLine(const std::string &source);

        bool ParseArmorHeaders(const std::string &source);

        bool ReadSignedTextLine(const std::string &source);

        bool ReadDataLine(const std::string &source);

        void ParseHeaderWord(const std::string &word);

        bool CheckCRCSum();

        ParserState state_;

        //MessageInfo message_info_;
        PGPMessagePtr message_;
    };
}

#endif /* cryptopg_PGPMessageParser_ */

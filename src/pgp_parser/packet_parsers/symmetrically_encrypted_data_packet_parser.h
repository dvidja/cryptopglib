//
//  SymmetricallyEncryptedDataPacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 10.5.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_SymmetricallyEncryptedDataPacketParser_
#define cryptopg_SymmetricallyEncryptedDataPacketParser_

#include <iostream>
#include "packet_parser.h"

namespace cryptopglib::pgp_parser::packet_parsers {

    class SymmetricallyEncryptedDataPacketParser : public PacketParser {
    public:
        explicit SymmetricallyEncryptedDataPacketParser(bool mdc = false);

        PGPPacket *Parse(ParsingDataBuffer &data_buffer, bool partial, int c) override;

    private:
        bool mdc_;
    };
}
#endif /* cryptopg_SymmetricallyEncryptedDataPacketParser_ */

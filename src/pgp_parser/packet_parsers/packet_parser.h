//
//  PacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 1.5.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_PacketParser_
#define cryptopg_PacketParser_

#include "../../pgp_data/pgp_packet.h"

namespace cryptopglib::pgp_parser::packet_parsers {
    using cryptopglib::pgp_data::PGPPacket;
    int GetPacketLengthForPartialContent(ParsingDataBuffer &data_buffer, bool &partial);


    class PacketParser {
    public:
        virtual PGPPacket *Parse(ParsingDataBuffer &data_buffer, bool partial, int c) = 0;

        virtual ~PacketParser();
    };
}
#endif /* cryptopg_PacketParser_ */

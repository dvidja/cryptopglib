//
//  PacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 1.5.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#pragma once

#include "../../pgp_data/pgp_packet.h"

namespace cryptopglib::pgp_parser::packet_parsers {
    using cryptopglib::pgp_data::PGPPacket;
    int GetPacketLengthForPartialContent(ParsingDataBuffer &data_buffer, bool &partial);

    class PacketParser {
    public:
        virtual PGPPacket *Parse(ParsingDataBuffer &data_buffer, bool partial, int c) = 0;

        virtual ~PacketParser();
    };

    std::unique_ptr<PacketParser> GetPacketParser(PacketType packet_type);
}

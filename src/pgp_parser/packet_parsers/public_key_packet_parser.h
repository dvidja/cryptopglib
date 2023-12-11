//
//  PublicKeyPacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 1.5.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_PublicKeyPacketParser_
#define cryptopg_PublicKeyPacketParser_

#include <iostream>
#include "packet_parser.h"

#include "../../pgp_data/packets/public_key_packet.h"

namespace cryptopglib::pgp_parser::packet_parsers {
    using pgp_data::packets::PublicKeyPacket;
    class PublicKeyPacketParser : public PacketParser {
    public:
        PublicKeyPacket *Parse(ParsingDataBuffer &data_buffer, bool partial, int c) override;

    };
}

#endif /* cryptopg_PublicKeyPacketParser_ */

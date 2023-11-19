//
//  MarkerPacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_MarkerPacketParser_
#define cryptopg_MarkerPacketParser_

#include "packet_parser.h"
#include "../../pgp_data/packets/marker_packet.h"

namespace cryptopglib::pgp_parser::packet_parsers {
    using pgp_data::packets::MarkerPacket;
    class MarkerPacketParser : public PacketParser {
    public:
        MarkerPacket *Parse(DataBuffer &data_buffer, bool partial, int c) override;

    };
}
#endif /* cryptopg_MarkerPacketParser_ */

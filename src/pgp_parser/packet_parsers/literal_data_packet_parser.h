//
//  LiteralDataPacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 11.8.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_LiteralDataPacketParser_
#define cryptopg_LiteralDataPacketParser_


#include "packet_parser.h"
#include "../../pgp_data/packets/literal_data_packet.h"

namespace cryptopglib::pgp_parser::packet_parsers {
    using pgp_data::packets::LiteralDataPacket;
    class LiteralDataPacketParser : public PacketParser {
    public:
        LiteralDataPacket *Parse(ParsingDataBuffer &data_buffer, bool partial, int c) override;

    private:
        LiteralDataPacket *ParsePartial(ParsingDataBuffer &data_buffer, int c);

    };
}

#endif /* cryptopg_LiteralDataPacketParser_ */

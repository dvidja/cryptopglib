//
//  TrustPacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_TrustPacketParser_
#define cryptopg_TrustPacketParser_

#include "packet_parser.h"
#include "../../pgp_data/packets/trust_packet.h"

namespace cryptopglib::pgp_parser::packet_parsers {
    using pgp_data::packets::TrustPacket;
    class TrustPacketParser : public PacketParser {
    public:
        TrustPacket *Parse(ParsingDataBuffer &data_buffer, bool partial, int c) override;

    };
}
#endif /* cryptopg_TrustPacketParser_ */

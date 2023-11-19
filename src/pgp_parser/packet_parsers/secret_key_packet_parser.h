//
//  SecretKeyPacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 1.5.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_SecretKeyPacketParser_
#define cryptopg_SecretKeyPacketParser_

#include "packet_parser.h"
#include "../../pgp_data/packets/secret_key_packet.h"

namespace cryptopglib::pgp_parser::packet_parsers {
    using pgp_data::packets::SecretKeyPacket;
    class SecretKeyPacketParser : public PacketParser {
    public:
        SecretKeyPacket *Parse(DataBuffer &data_buffer, bool partial, int c) override;
    };
}
#endif /* cryptopg_SecretKeyPacketParser_ */

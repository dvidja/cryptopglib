//
//  UserAttributePacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_UserAttributePacketParser_
#define cryptopg_UserAttributePacketParser_

#include "packet_parser.h"
#include "../../pgp_data/packets/user_attribute_packet.h"

namespace cryptopglib::pgp_parser::packet_parsers {
    using pgp_data::packets::UserAttributePacket;
    class UserAttributePacketParser : public PacketParser {
    public:
        UserAttributePacket *Parse(DataBuffer &data_buffer, bool partial, int c) override;

    };
}
#endif /* cryptopg_UserAttributePacketParser_ */

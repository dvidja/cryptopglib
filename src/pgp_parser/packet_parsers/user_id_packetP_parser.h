//
//  UserIDPacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 10.5.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_UserIDPacketParser_
#define cryptopg_UserIDPacketParser_

#include "packet_parser.h"
#include "../../pgp_data/packets/user_id_packet.h"

namespace cryptopglib::pgp_parser::packet_parsers {
    using cryptopglib::pgp_data::packets::UserIDPacket;
    class UserIDPacketParser : public PacketParser {
    public:
        UserIDPacket *Parse(DataBuffer &data_buffer, bool partial, int c) override;

    };
}
#endif /* cryptopg_UserIDPacketParser_ */

//
//  UserIDPacketParser.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 10.5.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "user_id_packetP_parser.h"
namespace cryptopglib::pgp_parser::packet_parsers {
    UserIDPacket *UserIDPacketParser::Parse(ParsingDataBuffer &data_buffer, bool partial, int c) {
        if (data_buffer.Length() > 2048) {
            return nullptr;
        }

        UserIDPacket *packet = new UserIDPacket();

        CharDataVector name = data_buffer.GetRangeOld(data_buffer.Length());
        packet->SetUserID(name);

        return packet;
    }
}
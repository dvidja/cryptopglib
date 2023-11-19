//
//  UserIDPacketParser.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 10.5.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "user_id_packetP_parser.h"
namespace cryptopglib::pgp_parser::packet_parsers {
    UserIDPacket *UserIDPacketParser::Parse(DataBuffer &data_buffer, bool partial, int c) {
        if (data_buffer.length() > 2048) {
            return nullptr;
        }

        UserIDPacket *packet = new UserIDPacket();

        CharDataVector name = data_buffer.GetRange(data_buffer.length());
        packet->SetUserID(name);

        return packet;
    }
}
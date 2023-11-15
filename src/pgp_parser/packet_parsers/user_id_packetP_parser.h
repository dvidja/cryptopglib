//
//  UserIDPacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 10.5.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__UserIDPacketParser__
#define __cryptopg__UserIDPacketParser__

#include "packet_parser.h"
#include "../../pgp_data/packets/user_id_packet.h"

class UserIDPacketParser : public PacketParser
{
public:
    UserIDPacket* Parse(DataBuffer& data_buffer, bool partial, int c) override;
    
};

#endif /* defined(__cryptopg__UserIDPacketParser__) */

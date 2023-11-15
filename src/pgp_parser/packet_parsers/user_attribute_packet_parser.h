//
//  UserAttributePacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__UserAttributePacketParser__
#define __cryptopg__UserAttributePacketParser__

#include "packet_parser.h"
#include "../../pgp_data/packets/user_attribute_packet.h"


class UserAttributePacketParser : public PacketParser
{
public:
    UserAttributePacket* Parse(DataBuffer& data_buffer, bool partial, int c) override;
    
};

#endif /* defined(__cryptopg__UserAttributePacketParser__) */

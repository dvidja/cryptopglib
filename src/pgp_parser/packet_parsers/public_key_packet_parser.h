//
//  PublicKeyPacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 1.5.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__PublicKeyPacketParser__
#define __cryptopg__PublicKeyPacketParser__

#include <iostream>
#include "packet_parser.h"

#include "../../pgp_data/packets/public_key_packet.h"


class PublicKeyPacketParser : public PacketParser
{
public:
    PublicKeyPacket* Parse(DataBuffer& data_buffer, bool partial, int c) override;
    
};

#endif /* defined(__cryptopg__PublicKeyPacketParser__) */

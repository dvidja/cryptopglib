//
//  PacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 1.5.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_PacketParser_
#define cryptopg_PacketParser_

#include "../../pgp_data/pgp_packet.h"


int GetPacketLengthForPartialContent(DataBuffer& data_buffer, bool& partial);


class PacketParser
{
public:
    virtual PGPPacket* Parse(DataBuffer& data_buffer, bool partial, int c) = 0;
    virtual ~PacketParser();
};

#endif /* cryptopg_PacketParser_ */

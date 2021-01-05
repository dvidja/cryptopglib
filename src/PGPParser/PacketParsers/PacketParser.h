//
//  PacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 1.5.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__PacketParser__
#define __cryptopg__PacketParser__

#include "../../PGPData/PGPPacket.h"


int GetPacketLengthForPartialContent(DataBuffer& data_buffer, bool& partial);


class PacketParser
{
public:
    virtual PGPPacket* Parse(DataBuffer& data_buffer, bool partial, int c = 0) = 0;
    virtual ~PacketParser();
};

#endif /* defined(__cryptopg__PacketParser__) */

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
#include "PacketParser.h"

#include "../../PGPData/Packets/PublicKeyPacket.h"


class PublicKeyPacketParser : public PacketParser
{
public:
    PublicKeyPacket* Parse(DataBuffer& data_buffer, bool partial, int c);
    
};

#endif /* defined(__cryptopg__PublicKeyPacketParser__) */

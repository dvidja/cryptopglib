//
//  MarkerPacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__MarkerPacketParser__
#define __cryptopg__MarkerPacketParser__

#include "PacketParser.h"
#include "../../PGPData/Packets/MarkerPacket.h"


class MarkerPacketParser : public PacketParser
{
public:
    MarkerPacket* Parse(DataBuffer& data_buffer, bool partial, int c) override;
    
};

#endif /* defined(__cryptopg__MarkerPacketParser__) */

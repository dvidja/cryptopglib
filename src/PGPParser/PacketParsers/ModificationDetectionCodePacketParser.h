//
//  ModificationDetectionPacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__ModificationDetectionCodePacketParser__
#define __cryptopg__ModificationDetectionCodePacketParser__

#include "PacketParser.h"
#include "../../PGPData/Packets/ModificationDetectionCodePacket.h"


class ModificationDetectionCodePacketParser : public PacketParser
{
public:
    ModificationDetectionCodePacket* Parse(DataBuffer& data_buffer, bool partial, int c);
    
};

#endif /* defined(__cryptopg__ModificationDetectionCodePacketParser__) */

//
//  CompressedDataPacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 11.8.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__CompressedDataPacketParser__
#define __cryptopg__CompressedDataPacketParser__

#include "PacketParser.h"
#include "../../PGPData/Packets/CompressedDataPacket.h"


class CompressedDataPacketParser : public PacketParser
{
public:
    CompressedDataPacket* Parse(DataBuffer& data_buffer, bool partial, int c);
    
};

#endif /* defined(__cryptopg__CompressedDataPacketParser__) */

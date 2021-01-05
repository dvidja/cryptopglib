//
//  TrustPacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__TrustPacketParser__
#define __cryptopg__TrustPacketParser__

#include "PacketParser.h"
#include "../../PGPData/Packets/TrustPacket.h"


class TrustPacketParser : public PacketParser
{
public:
    TrustPacket* Parse(DataBuffer& data_buffer, bool partial, int c) override;
    
};

#endif /* defined(__cryptopg__TrustPacketParser__) */

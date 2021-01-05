//
//  SecretKeyPacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 1.5.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__SecretKeyPacketParser__
#define __cryptopg__SecretKeyPacketParser__

#include "PacketParser.h"
#include "../../PGPData/Packets/SecretKeyPacket.h"


class SecretKeyPacketParser : public PacketParser
{
public:
    SecretKeyPacket* Parse(DataBuffer& data_buffer, bool partial, int c) override;
};
#endif /* defined(__cryptopg__SecretKeyPacketParser__) */

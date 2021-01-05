//
//  PublicKeyEnctyptedPacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 1.5.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__PublicKeyEnctyptedPacketParser__
#define __cryptopg__PublicKeyEnctyptedPacketParser__

#include "PacketParser.h"
#include "../../PGPData/Packets/PublicKeyEncryptedPacket.h"

class PublicKeyEnctyptedPacketParser : public PacketParser
{
public:
    PublicKeyEncryptedPacket* Parse(DataBuffer& data_buffer, bool partial, int c) override;
    
};

#endif /* defined(__cryptopg__PublicKeyEnctyptedPacketParser__) */

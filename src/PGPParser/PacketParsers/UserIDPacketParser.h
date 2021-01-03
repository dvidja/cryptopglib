//
//  UserIDPacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 10.5.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__UserIDPacketParser__
#define __cryptopg__UserIDPacketParser__

#include "PacketParser.h"
#include "../../PGPData/Packets/UserIDPacket.h"

class UserIDPacketParser : public PacketParser
{
public:
    UserIDPacket* Parse(DataBuffer& data_buffer, bool partial, int c);
    
};

#endif /* defined(__cryptopg__UserIDPacketParser__) */

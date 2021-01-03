//
//  SignaturePacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 1.5.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__SignaturePacketParser__
#define __cryptopg__SignaturePacketParser__

#include <iostream>
#include "PacketParser.h"
#include "../../PGPData/Packets/SignaturePacket.h"


class SignaturePacketParser : public PacketParser
{
public:
    SignaturePacket* Parse(DataBuffer& data_buffer, bool partial, int c);
    
private:
    SignaturePacket* ParseV3Packet(DataBuffer& data_buffer, bool partial);
    SignaturePacket* ParseV4Packet(DataBuffer& data_buffer, bool partial);
    
    void ParseSubpacket(DataBuffer data_buffer, SignaturePacket* packet, bool hashed);
};

#endif /* defined(__cryptopg__SignaturePacketParser__) */

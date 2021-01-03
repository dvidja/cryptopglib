//
//  OnePassSignaturePacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__OnePassSignaturePacketParser__
#define __cryptopg__OnePassSignaturePacketParser__

#include "PacketParser.h"
#include "../../PGPData/Packets/OnePassSignaturePacket.h"


class OnePassSignaturePacketParser : public PacketParser
{
public:
    OnePassSignaturePacket* Parse(DataBuffer& data_buffer, bool partial, int c);
    
};

#endif /* defined(__cryptopg__OnePassSignaturePacketParser__) */

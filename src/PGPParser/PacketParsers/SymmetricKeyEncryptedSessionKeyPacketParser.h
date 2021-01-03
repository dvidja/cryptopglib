//
//  SymmetricKeyEncryptedSessionKeyPacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__SymmetricKeyEncryptedSessionKeyPacketParser__
#define __cryptopg__SymmetricKeyEncryptedSessionKeyPacketParser__


#include "PacketParser.h"
#include "../../PGPData/Packets/SymmetricKeyEncryptedSessionKeyPacket.h"


class SymmetricKeyEncryptedSessionKeyPacketParser : public PacketParser
{
public:
    SymmetricKeyEncryptedSessionKeyPacket* Parse(DataBuffer& data_buffer, bool partial, int c);
    
};


#endif /* defined(__cryptopg__SymmetricKeyEncryptedSessionKeyPacketParser__) */

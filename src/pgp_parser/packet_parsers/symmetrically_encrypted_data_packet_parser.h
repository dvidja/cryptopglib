//
//  SymmetricallyEncryptedDataPacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 10.5.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__SymmetricallyEncryptedDataPacketParser__
#define __cryptopg__SymmetricallyEncryptedDataPacketParser__

#include <iostream>
#include "packet_parser.h"

class SymmetricallyEncryptedDataPacketParser : public PacketParser
{
public:
    SymmetricallyEncryptedDataPacketParser(bool mdc = false);
    
    PGPPacket* Parse(DataBuffer& data_buffer, bool partial, int c) override;
    
private:
    bool mdc_;
};

#endif /* defined(__cryptopg__SymmetricallyEncryptedDataPacketParser__) */

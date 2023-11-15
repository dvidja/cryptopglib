//
//  LiteralDataPacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 11.8.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__LiteralDataPacketParser__
#define __cryptopg__LiteralDataPacketParser__


#include "packet_parser.h"
#include "../../pgp_data/packets/literal_data_packet.h"


class LiteralDataPacketParser : public PacketParser
{
public:
    LiteralDataPacket* Parse(DataBuffer& data_buffer, bool partial, int c) override;
    
private:
    LiteralDataPacket* ParsePartial(DataBuffer& data_buffer, int c);
    
};


#endif /* defined(__cryptopg__LiteralDataPacketParser__) */

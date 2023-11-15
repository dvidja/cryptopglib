//
//  OnePassSignaturePacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__OnePassSignaturePacketParser__
#define __cryptopg__OnePassSignaturePacketParser__

#include "packet_parser.h"
#include "../../pgp_data/packets/one_pass_signature_packet.h"


class OnePassSignaturePacketParser : public PacketParser
{
public:
    OnePassSignaturePacket* Parse(DataBuffer& data_buffer, bool partial, int c) override;
    
};

#endif /* defined(__cryptopg__OnePassSignaturePacketParser__) */

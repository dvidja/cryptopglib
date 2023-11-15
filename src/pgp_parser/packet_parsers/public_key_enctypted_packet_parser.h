//
//  PublicKeyEnctyptedPacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 1.5.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__PublicKeyEnctyptedPacketParser__
#define __cryptopg__PublicKeyEnctyptedPacketParser__

#include "packet_parser.h"
#include "../../pgp_data/packets/public_key_encrypted_packet.h"

class PublicKeyEnctyptedPacketParser : public PacketParser
{
public:
    PublicKeyEncryptedPacket* Parse(DataBuffer& data_buffer, bool partial, int c) override;
    
};

#endif /* defined(__cryptopg__PublicKeyEnctyptedPacketParser__) */

//
//  SymmetricKeyEncryptedSessionKeyPacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__SymmetricKeyEncryptedSessionKeyPacketParser__
#define __cryptopg__SymmetricKeyEncryptedSessionKeyPacketParser__


#include "packet_parser.h"
#include "../../pgp_data/packets/symmetric_key_encrypted_session_key_packet.h"


class SymmetricKeyEncryptedSessionKeyPacketParser : public PacketParser
{
public:
    SymmetricKeyEncryptedSessionKeyPacket* Parse(DataBuffer& data_buffer, bool partial, int c) override;
    
};


#endif /* defined(__cryptopg__SymmetricKeyEncryptedSessionKeyPacketParser__) */

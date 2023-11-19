//
//  SymmetricKeyEncryptedSessionKeyPacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_SymmetricKeyEncryptedSessionKeyPacketParser_
#define cryptopg_SymmetricKeyEncryptedSessionKeyPacketParser_


#include "packet_parser.h"
#include "../../pgp_data/packets/symmetric_key_encrypted_session_key_packet.h"

namespace cryptopglib::pgp_parser::packet_parsers {
    using pgp_data::packets::SymmetricKeyEncryptedSessionKeyPacket;
    class SymmetricKeyEncryptedSessionKeyPacketParser : public PacketParser {
    public:
        SymmetricKeyEncryptedSessionKeyPacket *Parse(DataBuffer &data_buffer, bool partial, int c) override;

    };
}

#endif /* cryptopg_SymmetricKeyEncryptedSessionKeyPacketParser_ */

//
//  PublicKeyEnctyptedPacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 1.5.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_PublicKeyEncryptedPacketParser_
#define cryptopg_PublicKeyEncryptedPacketParser_

#include "packet_parser.h"
#include "../../pgp_data/packets/public_key_encrypted_packet.h"

namespace cryptopglib::pgp_parser::packet_parsers {
    using pgp_data::packets::PublicKeyEncryptedPacket;
    class PublicKeyEncryptedPacketParser : public PacketParser {
    public:
        PublicKeyEncryptedPacket *Parse(ParsingDataBuffer &data_buffer, bool partial, int c) override;

    };
}
#endif /* cryptopg_PublicKeyEncryptedPacketParser_ */

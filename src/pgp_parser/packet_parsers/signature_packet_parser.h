//
//  SignaturePacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 1.5.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_SignaturePacketParser_
#define cryptopg_SignaturePacketParser_

#include <iostream>
#include "packet_parser.h"
#include "../../pgp_data/packets/signature_packet.h"

namespace cryptopglib::pgp_parser::packet_parsers {
    using pgp_data::packets::SignaturePacket;
    class SignaturePacketParser : public PacketParser {
    public:
        SignaturePacket *Parse(ParsingDataBuffer &data_buffer, bool partial, int c) override;

    private:
        SignaturePacket *ParseV3Packet(ParsingDataBuffer &data_buffer, bool partial);

        SignaturePacket *ParseV4Packet(ParsingDataBuffer &data_buffer, bool partial);

        void ParseSubPacket(ParsingDataBuffer data_buffer, SignaturePacket *packet, bool hashed);
    };
}
#endif /* cryptopg_SignaturePacketParser_ */

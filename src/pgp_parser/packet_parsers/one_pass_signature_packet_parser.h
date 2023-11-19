//
//  OnePassSignaturePacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_OnePassSignaturePacketParser_
#define cryptopg_OnePassSignaturePacketParser_

#include "packet_parser.h"
#include "../../pgp_data/packets/one_pass_signature_packet.h"

namespace cryptopglib::pgp_parser::packet_parsers {
    using pgp_data::packets::OnePassSignaturePacket;
    class OnePassSignaturePacketParser : public PacketParser {
    public:
        OnePassSignaturePacket *Parse(DataBuffer &data_buffer, bool partial, int c) override;

    };
}
#endif /* cryptopg_OnePassSignaturePacketParser_ */

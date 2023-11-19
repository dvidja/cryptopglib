//
//  CompressedDataPacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 11.8.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_CompressedDataPacketParser_
#define cryptopg_CompressedDataPacketParser_

#include "packet_parser.h"
#include "../../pgp_data/packets/compressed_data_packet.h"

namespace cryptopglib::pgp_parser::packet_parsers {
    using pgp_data::packets::CompressedDataPacket;
    class CompressedDataPacketParser : public PacketParser {
    public:
        CompressedDataPacket *Parse(DataBuffer &data_buffer, bool partial, int c) override;

    };
}
#endif /* cryptopg_CompressedDataPacketParser_ */

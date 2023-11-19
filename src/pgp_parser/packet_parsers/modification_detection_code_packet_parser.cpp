//
//  ModificationDetectionPacketParser.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "modification_detection_code_packet_parser.h"

namespace cryptopglib::pgp_parser::packet_parsers {
    ModificationDetectionCodePacket *
    ModificationDetectionCodePacketParser::Parse(DataBuffer &data_buffer, bool partial, int c) {
        if (data_buffer.length() != 20) {
            // TODO: handle error
            //
            return nullptr;
        }

        ModificationDetectionCodePacket *packet = new ModificationDetectionCodePacket;
        packet->SetData(data_buffer.GetRawData());

        return packet;
    }
}
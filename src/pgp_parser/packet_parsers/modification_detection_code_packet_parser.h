//
//  ModificationDetectionPacketParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_ModificationDetectionCodePacketParser_
#define cryptopg_ModificationDetectionCodePacketParser_

#include "packet_parser.h"
#include "../../pgp_data/packets/modification_detection_code_packet.h"


class ModificationDetectionCodePacketParser : public PacketParser
{
public:
    ModificationDetectionCodePacket* Parse(DataBuffer& data_buffer, bool partial, int c) override;
    
};

#endif /* cryptopg_ModificationDetectionCodePacketParser_ */

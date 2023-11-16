//
//  PGPPacketsParser.h
//  cryptopg
//
//  Created by Anton Sarychev on 18.4.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_PGPPacketsParser_
#define cryptopg_PGPPacketsParser_

#include <iostream>
#include <vector>
#include <memory>

#include "../pgp_data/pgp_packet.h"
#include "../utils/data_buffer.h"
#include "packet_parsers/packet_parser.h"

class PGPPacketsParser
{
public:
    explicit PGPPacketsParser(const CharDataVector &data);
    
    PGPPacketsArray ParsePackets();
    
    void GetUserIDPacketsRawData(CharDataVector& user_id_data, int user_id_number);
    void GetKeyPacketsRawData(CharDataVector& key_data, int key_number);
    void GetV4HashedSignatureData(CharDataVector& signature_data, int signature_number);
    
private:
    void ParsePacket();
    void ParsePacket(int packet_type, unsigned long packet_length, bool partial);
    void SkipPacket(unsigned long packet_length, bool partial);
    
    std::unique_ptr<PacketParser> CreatePacketParser(int packet_type);
    
    
private:
    DataBuffer data_buffer_;
    PGPPacketsArray packets_;
};

#endif /* cryptopg_PGPPacketsParser_ */

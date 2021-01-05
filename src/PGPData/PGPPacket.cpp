//
//  PGPPacket.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 18.4.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "PGPPacket.h"

#include <cmath>


namespace packet_helper
{
    double log2(double n)
    {
        return log(n) / log(2.0);
    }

    void GetKeyIDData(const KeyIDData& key_id, CharDataVector& key_id_data)
    {
        key_id_data.clear();
        
        key_id_data.push_back((key_id[0] >> 24) & 0xFF);
        key_id_data.push_back((key_id[0] >> 16) & 0xFF);
        key_id_data.push_back((key_id[0] >> 8) & 0xFF);
        key_id_data.push_back(key_id[0] & 0xFF);
        
        key_id_data.push_back((key_id[1] >> 24) & 0xFF);
        key_id_data.push_back((key_id[1] >> 16) & 0xFF);
        key_id_data.push_back((key_id[1] >> 8) & 0xFF);
        key_id_data.push_back(key_id[1] & 0xFF);
    }
}


PGPPacket::PGPPacket(const PacketType packet_type)
    : packet_type_(packet_type)
{
    
}

PGPPacket::~PGPPacket()
{

}

PacketType PGPPacket::GetPacketType()
{
    return packet_type_;
}
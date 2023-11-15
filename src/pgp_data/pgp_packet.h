//
//  PGPPacket.h
//  cryptopg
//
//  Created by Anton Sarychev on 18.4.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__PGPPacket__
#define __cryptopg__PGPPacket__

#include "pgp_packet_types.h"
#include "../Utils/data_buffer.h"


namespace  packet_helper
{
    double log2(double n);
    void GetKeyIDData(const KeyIDData& key_id, CharDataVector& key_id_data);
}

class PGPPacket
{
public:
    PGPPacket(const PacketType packet_type);
    virtual ~PGPPacket();
    
    PacketType GetPacketType();
    
    virtual bool GetRawData(CharDataVector& data) = 0;
    virtual bool GetBinaryData(CharDataVector& data) = 0;
    
private:
    const PacketType packet_type_;
};

typedef std::shared_ptr<PGPPacket> PGPPacketPtr;
typedef std::vector<PGPPacketPtr> PGPPacketsArray;

#endif /* defined(__cryptopg__PGPPacket__) */

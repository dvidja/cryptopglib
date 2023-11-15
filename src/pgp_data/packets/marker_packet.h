//
//  MarkerPacket.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__MarkerPacket__
#define __cryptopg__MarkerPacket__

#include "../pgp_packet.h"

class MarkerPacket : public PGPPacket
{
public:
    MarkerPacket();
    
    void SetData(CharDataVector& data);
    CharDataVector& GetData();
    
    virtual bool GetRawData(CharDataVector& data);
    virtual bool GetBinaryData(CharDataVector& data);
    
private:
    CharDataVector data_;
};

typedef std::shared_ptr<MarkerPacket> MarkerPacketPtr;

#endif /* defined(__cryptopg__MarkerPacket__) */

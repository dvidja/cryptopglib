//
//  MarkerPacket.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_MarkerPacket_
#define cryptopg_MarkerPacket_

#include "../pgp_packet.h"

class MarkerPacket : public PGPPacket
{
public:
    MarkerPacket();
    
    void SetData(CharDataVector& data);
    CharDataVector& GetData();
    
    bool GetRawData(CharDataVector& data) override;
    bool GetBinaryData(CharDataVector& data) override;
    
private:
    CharDataVector data_;
};

typedef std::shared_ptr<MarkerPacket> MarkerPacketPtr;

#endif /* cryptopg_MarkerPacket_ */

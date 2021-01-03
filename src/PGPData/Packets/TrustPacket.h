//
//  TrustPacket.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__TrustPacket__
#define __cryptopg__TrustPacket__

#include "../PGPPacket.h"

class TrustPacket : public PGPPacket
{
public:
    TrustPacket();
    
    virtual bool GetRawData(CharDataVector& data);
    virtual bool GetBinaryData(CharDataVector& data);
};

typedef std::shared_ptr<TrustPacket> TrustPacketPtr;

#endif /* defined(__cryptopg__TrustPacket__) */

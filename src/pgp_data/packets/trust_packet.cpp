//
//  TrustPacket.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "trust_packet.h"


TrustPacket::TrustPacket()
    : PGPPacket(PT_TRUST_PACKET)
{
    
}

bool TrustPacket::GetRawData(CharDataVector& data)
{
    return false;
}

bool TrustPacket::GetBinaryData(CharDataVector& data)
{
    return false;
}

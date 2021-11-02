//
//  UserAttributePacket.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "UserAttributePacket.h"


UserAttributePacket::UserAttributePacket()
    : PGPPacket(PT_USER_ATTRIBUTE_PACKET)
{
    
}

bool UserAttributePacket::GetRawData(CharDataVector &data)
{
    return false;
}

bool UserAttributePacket::GetBinaryData(CharDataVector& data)
{
    return false;
}
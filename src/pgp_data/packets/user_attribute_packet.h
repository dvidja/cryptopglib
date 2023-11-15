//
//  UserAttributePacket.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__UserAttributePacket__
#define __cryptopg__UserAttributePacket__

#include "../pgp_packet.h"

class UserAttributePacket : public PGPPacket
{
public:
    UserAttributePacket();
    
    virtual bool GetRawData(CharDataVector& data);
    virtual bool GetBinaryData(CharDataVector& data);
};

typedef std::shared_ptr<UserAttributePacket> UserAttributePacketPtr;

#endif /* defined(__cryptopg__UserAttributePacket__) */

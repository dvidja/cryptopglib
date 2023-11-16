//
//  UserAttributePacket.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_UserAttributePacket_
#define cryptopg_UserAttributePacket_

#include "../pgp_packet.h"

class UserAttributePacket : public PGPPacket
{
public:
    UserAttributePacket();
    
    bool GetRawData(CharDataVector& data) override;
    bool GetBinaryData(CharDataVector& data) override;
};

typedef std::shared_ptr<UserAttributePacket> UserAttributePacketPtr;

#endif /* cryptopg_UserAttributePacket_ */

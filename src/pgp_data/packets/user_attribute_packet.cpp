//
//  UserAttributePacket.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "user_attribute_packet.h"

namespace cryptopglib::pgp_data::packets {
    UserAttributePacket::UserAttributePacket()
            : PGPPacket(PacketType::kUserAttributePacket) {

    }

    bool UserAttributePacket::GetRawData(CharDataVector &data) {
        return false;
    }

    bool UserAttributePacket::GetBinaryData(CharDataVector &data) {
        return false;
    }
}

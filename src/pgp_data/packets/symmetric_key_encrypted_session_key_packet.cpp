//
//  SymmetricKeyEncryptedSessionKeyPacket.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "symmetric_key_encrypted_session_key_packet.h"

namespace cryptopglib::pgp_data::packets {
    SymmetricKeyEncryptedSessionKeyPacket::SymmetricKeyEncryptedSessionKeyPacket()
            : PGPPacket(PacketType::kSymmetricKeyEncryptedSessionKeyPacket) {

    }

    bool SymmetricKeyEncryptedSessionKeyPacket::GetRawData(CharDataVector &data) {
        return false;
    }

    bool SymmetricKeyEncryptedSessionKeyPacket::GetBinaryData(CharDataVector &data) {
        return false;
    }
}

//
//  SymmetricKeyEncryptedSessionKeyPacket.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "SymmetricKeyEncryptedSessionKeyPacket.h"


SymmetricKeyEncryptedSessionKeyPacket::SymmetricKeyEncryptedSessionKeyPacket()
    : PGPPacket(PT_SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY_PACKET)
{
    
}

bool SymmetricKeyEncryptedSessionKeyPacket::GetRawData(CharDataVector& data)
{
    return false;
}

bool SymmetricKeyEncryptedSessionKeyPacket::GetBinaryData(CharDataVector& data)
{
    return false;
}

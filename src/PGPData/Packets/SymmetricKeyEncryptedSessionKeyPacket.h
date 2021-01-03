//
//  SymmetricKeyEncryptedSessionKeyPacket.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__SymmetricKeyEncryptedSessionKeyPacket__
#define __cryptopg__SymmetricKeyEncryptedSessionKeyPacket__

#include "../PGPPacket.h"

class SymmetricKeyEncryptedSessionKeyPacket : public PGPPacket
{
public:
    SymmetricKeyEncryptedSessionKeyPacket();
    
    virtual bool GetRawData(CharDataVector& data);
    virtual bool GetBinaryData(CharDataVector& data);
};

typedef std::shared_ptr<SymmetricKeyEncryptedSessionKeyPacket> SymmetricKeyEncryptedSessionKeyPacketPtr;

#endif /* defined(__cryptopg__SymmetricKeyEncryptedSessionKeyPacket__) */

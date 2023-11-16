//
//  SymmetricKeyEncryptedSessionKeyPacket.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_SymmetricKeyEncryptedSessionKeyPacket_
#define cryptopg_SymmetricKeyEncryptedSessionKeyPacket_

#include "../pgp_packet.h"

class SymmetricKeyEncryptedSessionKeyPacket : public PGPPacket
{
public:
    SymmetricKeyEncryptedSessionKeyPacket();
    
    bool GetRawData(CharDataVector& data) override;
    bool GetBinaryData(CharDataVector& data) override;
};

typedef std::shared_ptr<SymmetricKeyEncryptedSessionKeyPacket> SymmetricKeyEncryptedSessionKeyPacketPtr;

#endif /* cryptopg_SymmetricKeyEncryptedSessionKeyPacket_ */

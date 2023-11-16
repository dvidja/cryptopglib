//
//  TrustPacket.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_TrustPacket_
#define cryptopg_TrustPacket_

#include "../pgp_packet.h"

class TrustPacket : public PGPPacket
{
public:
    TrustPacket();
    
    bool GetRawData(CharDataVector& data) override;
    bool GetBinaryData(CharDataVector& data) override;
};

typedef std::shared_ptr<TrustPacket> TrustPacketPtr;

#endif /* cryptopg_TrustPacket_ */

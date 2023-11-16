//
//  ModificationDetectionCodePacket.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_ModificationDetectionCodePacket_
#define cryptopg_ModificationDetectionCodePacket_

#include "../pgp_packet.h"

class ModificationDetectionCodePacket : public PGPPacket
{
public:
    ModificationDetectionCodePacket();
    
    void SetData(const CharDataVector& data);
    CharDataVector& GetData();
    
    bool GetRawData(CharDataVector& data) override;
    bool GetBinaryData(CharDataVector& data) override;
    
private:
    
    CharDataVector data_;
};

typedef std::shared_ptr<ModificationDetectionCodePacket> ModificationDetectionCodePacketPtr;

#endif /* cryptopg_ModificationDetectionCodePacket_ */

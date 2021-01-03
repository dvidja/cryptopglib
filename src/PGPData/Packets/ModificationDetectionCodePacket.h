//
//  ModificationDetectionCodePacket.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__ModificationDetectionCodePacket__
#define __cryptopg__ModificationDetectionCodePacket__

#include "../PGPPacket.h"

class ModificationDetectionCodePacket : public PGPPacket
{
public:
    ModificationDetectionCodePacket();
    
    void SetData(const CharDataVector& data);
    CharDataVector& GetData();
    
    virtual bool GetRawData(CharDataVector& data);
    virtual bool GetBinaryData(CharDataVector& data);
    
private:
    
    CharDataVector data_;
};

typedef std::shared_ptr<ModificationDetectionCodePacket> ModificationDetectionCodePacketPtr;

#endif /* defined(__cryptopg__ModificationDetectionCodePacket__) */

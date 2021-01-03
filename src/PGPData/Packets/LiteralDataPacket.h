//
//  LiteralDataPacket.h
//  cryptopg
//
//  Created by Anton Sarychev on 11.8.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__LiteralDataPacket__
#define __cryptopg__LiteralDataPacket__

#include "../PGPPacket.h"


class LiteralDataPacket : public PGPPacket
{
public:
    LiteralDataPacket();
    
    void SetData(const CharDataVector& data);
    void SetFileName(const CharDataVector& file_name);
    
    CharDataVector& GetData();
    CharDataVector& GetFileName();
    
    virtual bool GetRawData(CharDataVector& data);
    virtual bool GetBinaryData(CharDataVector& data);
    
private:

    CharDataVector data_;
    CharDataVector file_name_;
};


typedef std::shared_ptr<LiteralDataPacket> LiteralDataPacketPtr;

#endif /* defined(__cryptopg__LiteralDataPacket__) */

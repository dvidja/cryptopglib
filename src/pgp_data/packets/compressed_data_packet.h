//
//  CompressedDataPacket.h
//  cryptopg
//
//  Created by Anton Sarychev on 11.8.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__CompressedDataPacket__
#define __cryptopg__CompressedDataPacket__

#include "../pgp_packet.h"
#include "../../crypto/compression_algorithms.h"


class CompressedDataPacket : public PGPPacket
{
public:
    CompressedDataPacket();
    
    void SetCompressAlgorithm(CompressionAlgorithms compress_algo);
    void SetData(const CharDataVector& data);
    
    CompressionAlgorithms GetCompressAlgorithm();
    CharDataVector& GetData();
    
    virtual bool GetRawData(CharDataVector& data);
    virtual bool GetBinaryData(CharDataVector& data);

private:
    CompressionAlgorithms compress_algo_;
    CharDataVector data_;
};

typedef std::shared_ptr<CompressedDataPacket> CompressedDataPacketPtr;

#endif /* defined(__cryptopg__CompressedDataPacket__) */

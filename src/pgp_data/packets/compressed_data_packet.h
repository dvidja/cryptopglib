//
//  CompressedDataPacket.h
//  cryptopg
//
//  Created by Anton Sarychev on 11.8.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_CompressedDataPacket_
#define cryptopg_CompressedDataPacket_

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
    
    bool GetRawData(CharDataVector& data) override;
    bool GetBinaryData(CharDataVector& data) override;

private:
    CompressionAlgorithms compress_algo_;
    CharDataVector data_;
};

typedef std::shared_ptr<CompressedDataPacket> CompressedDataPacketPtr;

#endif /* cryptopg_CompressedDataPacket_ */

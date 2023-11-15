//
//  CompressedDataPacket.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 11.8.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "compressed_data_packet.h"

CompressedDataPacket::CompressedDataPacket()
    : PGPPacket(PT_COMPRESSED_DATA_PACKET)
{
    
}

void CompressedDataPacket::SetCompressAlgorithm(CompressionAlgorithms compress_algo)
{
    compress_algo_ = compress_algo;
}

void CompressedDataPacket::SetData(const CharDataVector& data)
{
    data_.assign(data.begin(), data.end());
}

CompressionAlgorithms CompressedDataPacket::GetCompressAlgorithm()
{
    return compress_algo_;
}

CharDataVector& CompressedDataPacket::GetData()
{
    return data_;
}

bool CompressedDataPacket::GetRawData(CharDataVector &data)
{
    CharDataVector temp_data;
    
    temp_data.push_back(GetCompressAlgorithm());
    temp_data.insert(temp_data.end(), data_.begin(), data_.end());
    
    data.insert(data.end(), temp_data.begin(), temp_data.end());
    
    return true;
}

bool CompressedDataPacket::GetBinaryData(CharDataVector& data)
{
    CharDataVector temp_data;
    
    if(!GetRawData(temp_data))
    {
        return false;
    }
    
    ///////////////////////////////
    unsigned char c = 0;
    c ^= 0x80;
    c ^= 0x40;
    c ^= GetPacketType();
    data.push_back(c);
    
    if (temp_data.size() < 192)
    {
        data.push_back(temp_data.size());
    }
    else if (temp_data.size() < 8384)
    {
        int length = static_cast<int>(temp_data.size()) - 192;
        data.push_back((length / 256) + 192);
        data.push_back(length % 256);
    }
    else
    {
        int length = static_cast<int>(temp_data.size());
        data.push_back(0xff);
        data.push_back((length >> 24) & 0xff);
        data.push_back((length >> 16) & 0xff);
        data.push_back((length >> 8) & 0xff);
        data.push_back(length & 0xff);
    }
    
    data.insert(data.end(), temp_data.begin(), temp_data.end());
    
    return true;
}

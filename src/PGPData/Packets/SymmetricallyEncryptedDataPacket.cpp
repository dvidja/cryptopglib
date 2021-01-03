//
//  SymmetricallyEncryptedDataPacket.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 6.8.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "SymmetricallyEncryptedDataPacket.h"


SymmetricallyEncryptedDataPacket::SymmetricallyEncryptedDataPacket(PacketType packet_type)
    : PGPPacket(packet_type)
{
    
}

void SymmetricallyEncryptedDataPacket::SetEncryptedData(CharDataVector& encrypted_data)
{
    encrypted_data_.assign(encrypted_data.begin(), encrypted_data.end());
}

const CharDataVector& SymmetricallyEncryptedDataPacket::GetEncryptedData()
{
    return encrypted_data_;
}

void SymmetricallyEncryptedDataPacket::SetMDCData(CharDataVector& encrypted_data)
{
    mdc_data_.assign(encrypted_data.begin(), encrypted_data.end());
}

const CharDataVector& SymmetricallyEncryptedDataPacket::GetMDCData()
{
    return mdc_data_;
}

bool SymmetricallyEncryptedDataPacket::GetRawData(CharDataVector &data)
{
    CharDataVector temp_data;
    if (GetPacketType() == PT_SYMMETRIC_ENCRYTPED_AND_INTEGRITY_PROTECTED_DATA_PACKET)
    {
        temp_data.push_back(1);
    }
    temp_data.insert(temp_data.end(), encrypted_data_.begin(), encrypted_data_.end());
    
    data.insert(data.end(), temp_data.begin(), temp_data.end());
    
    return true;
    
}

bool SymmetricallyEncryptedDataPacket::GetBinaryData(CharDataVector& data)
{
    CharDataVector temp_data;
    if (!GetRawData(temp_data))
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


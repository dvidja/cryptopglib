//
//  DataBuffer.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 14.4.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "data_buffer.h"

#include <utility>


DataBuffer::DataBuffer()
    : current_position_(0)
{
}

DataBuffer::DataBuffer(const int size)
    : current_position_(0)
{
}

DataBuffer::DataBuffer(CharDataVector  data)
    : current_position_(0)
    , data_(std::move(data))
{
    
}

unsigned char DataBuffer::GetNextByte()
{
    if (current_position_ < data_.size())
    {
        unsigned char c = data_[current_position_];
        current_position_++;
        
        return c;
    }
    
    return -1;
}

unsigned char DataBuffer::GetNextByteNotEOF()
{
    return GetNextByte() & 0xFF;
}

unsigned short DataBuffer::GetNextTwoOctets()
{
    unsigned short a;
    
    a = GetNextByteNotEOF() << 8;
    a |= GetNextByteNotEOF();
    
    return a;
}

CharDataVector DataBuffer::GetRange(size_t length)
{
    size_t end = length + current_position_;
    if (current_position_ >= end)
    {
        return {};
    }
    
    if (end > data_.size())
    {
        CharDataVector result(data_.begin() + current_position_, data_.end());
        current_position_ = data_.size();
        return result;
    }
    
    CharDataVector result(data_.begin() + current_position_, data_.begin() + end);
    current_position_ += length;
    
    return result;
}

CharDataVector DataBuffer::GetRange(size_t start_pos, size_t last_pos)
{
    if (last_pos >= data_.size())
    {
        return {};
    }
    
    CharDataVector result(data_.begin() + start_pos, data_.begin() + last_pos);
    current_position_ = last_pos;
    return result;
}

CharDataVector DataBuffer::GetRawData()
{
    return data_;
}

unsigned int DataBuffer::GetNextFourOctets()
{
    unsigned int a;
    a = GetNextByteNotEOF() << 24;
    a |= GetNextByteNotEOF() << 16;
    a |= GetNextByteNotEOF() << 8;
    a |= GetNextByteNotEOF();
    
    return a;
}

bool DataBuffer::HasNextByte()
{
    return current_position_ < (data_.size() - 1);
}

void DataBuffer::ResetCurrentPosition()
{
    current_position_ = 0;
}

bool DataBuffer::Skip(unsigned long packet_length)
{
    current_position_ += packet_length;
    
    
    return current_position_ < data_.size();
}

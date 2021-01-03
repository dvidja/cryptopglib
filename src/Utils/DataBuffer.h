//
//  DataBuffer.h
//  cryptopg
//
//  Created by Anton Sarychev on 14.4.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__DataBuffer__
#define __cryptopg__DataBuffer__

#include <iostream>

//#include "../PGPData/PGPDataTypes.h"


class DataBuffer
{
public:
    DataBuffer();
    DataBuffer(const int size);
    DataBuffer(const CharDataVector& data);
    
    unsigned char GetNextByte();
    unsigned char GetNextByteNotEOF();
    unsigned short GetNextTwoOctets();
    unsigned int GetNextFourOctets();
    
    bool Skip(unsigned long packet_length);
    
    CharDataVector GetRange(size_t length);
    CharDataVector GetRange(size_t start_pos, size_t last_pos);
    CharDataVector GetRawData();
    
    bool HasNextByte();
    void ResetCurrentPosition();
    
    bool empty() { return data_.empty(); }
    size_t length() { return data_.size(); }
    size_t rest_length() { return data_.size() - current_position_; };
    size_t current_position(){ return current_position_; };
    
private:
    CharDataVector data_;
    size_t current_position_;
};

#endif /* defined(__cryptopg__DataBuffer__) */

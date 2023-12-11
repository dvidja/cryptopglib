//
//  DataBuffer.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 14.4.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "parsing_data_buffer.h"

#include <utility>
#include <cassert>

namespace cryptopglib {
    ParsingDataBuffer::ParsingDataBuffer(CharDataVector data)
            : currentPosition(0)
            , data(std::move(data)) {
    }

    unsigned char ParsingDataBuffer::GetNextByte() {
        currentPosition++;
        assert(currentPosition < data.size());
        return data[currentPosition];
    }

    unsigned char ParsingDataBuffer::GetNextByteNotEOF() {
        return GetNextByte() & 0xFF;
    }

    unsigned short ParsingDataBuffer::GetNextTwoOctets() {
        unsigned short a = GetNextByteNotEOF() << 8;
        a |= GetNextByteNotEOF();
        return a;
    }

    CharDataVector ParsingDataBuffer::GetRange(size_t length) {
        size_t end = length + currentPosition;

        if (end > data.size()) {
            CharDataVector result(data.begin() + currentPosition, data.end());
            currentPosition = data.size();
            return result;
        }

        CharDataVector result(data.begin() + currentPosition, data.begin() + end);
        currentPosition += length;

        return result;
    }

    CharDataVector ParsingDataBuffer::GetRange(size_t start_pos, size_t last_pos) {
        if (last_pos >= data.size()) {
            return {};
        }

        CharDataVector result(data.begin() + start_pos, data.begin() + last_pos);
        currentPosition = last_pos;
        return result;
    }

    CharDataVector ParsingDataBuffer::GetRawData() {
        return data;
    }

    unsigned int ParsingDataBuffer::GetNextFourOctets() {
        unsigned int a;
        a = GetNextByteNotEOF() << 24;
        a |= GetNextByteNotEOF() << 16;
        a |= GetNextByteNotEOF() << 8;
        a |= GetNextByteNotEOF();

        return a;
    }

    bool ParsingDataBuffer::HasNextByte() {
        return currentPosition < (data.size() - 1);
    }

    void ParsingDataBuffer::ResetCurrentPosition() {
        currentPosition = 0;
    }

    bool ParsingDataBuffer::Skip(unsigned long packet_length) {
        currentPosition += packet_length;


        return currentPosition < data.size();
    }
}
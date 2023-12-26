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
            , data(data)
            , dataHandler(data){
    }

    ParsingDataBuffer::ParsingDataBuffer(std::span<unsigned char> data)
            : currentPosition(0)
            , dataHandler(data){
    }

    unsigned char ParsingDataBuffer::GetNextByte() {
        currentPosition++;
        assert(currentPosition < data.size());
        return data[currentPosition];
    }

    unsigned char ParsingDataBuffer::GetCurrentByte() {
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

    ParsingDataBuffer ParsingDataBuffer::GetRange(size_t length) {
        size_t end = length + currentPosition;

        if (end > data.size()) {
            return ParsingDataBuffer{std::span<unsigned char>(data.begin() + currentPosition, data.end())};
        }

        auto temp_span = std::span<unsigned char>(data.begin() + currentPosition, data.begin() + end);
        //ParsingDataBuffer result(std::span<unsigned char>(data.begin() + currentPosition, data.begin() + end));
        currentPosition += length;

        return ParsingDataBuffer(temp_span);
    }

    ParsingDataBuffer ParsingDataBuffer::GetRange(size_t start_pos, size_t last_pos) {
        assert(last_pos < data.size());
        auto temp_span = std::span<unsigned char>(data.begin() + start_pos, data.begin() + last_pos);
        //ParsingDataBuffer result(std::span<unsigned char>(data.begin() + start_pos, data.begin() + last_pos));
        currentPosition = last_pos;
        return ParsingDataBuffer(temp_span);
    }

    ParsingDataBuffer ParsingDataBuffer::GetRawData() {
        return ParsingDataBuffer(std::span<unsigned char>(data.begin(), data.end()));
    }

    CharDataVector ParsingDataBuffer::GetRangeOld(size_t length) {
        size_t end = length + currentPosition;

        if (end > data.size()) {
            //return ParsingDataSubBuffer{std::span<unsigned char>(data.begin() + currentPosition, data.end())};
            return CharDataVector(data.begin() + currentPosition, data.end());
        }

        CharDataVector result(data.begin() + currentPosition, data.begin() + end);
        currentPosition += length;

        return {data.begin() + currentPosition, data.begin() + end};
    }

    CharDataVector ParsingDataBuffer::GetRangeOld(size_t start_pos, size_t last_pos) {
        assert(last_pos < data.size());
        CharDataVector result(data.begin() + start_pos, data.begin() + last_pos);
        currentPosition = last_pos;
        return result;
    }

    CharDataVector ParsingDataBuffer::GetRawDataOld() {
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
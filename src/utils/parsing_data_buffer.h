//
//  DataBuffer.h
//  cryptopg
//
//  Created by Anton Sarychev on 14.4.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//
#pragma once

#include <iostream>
#include <span>

#include "../pgp_data/pgp_data_types.h"

namespace cryptopglib {

    class ParsingDataSubBuffer {
    public:
        explicit ParsingDataSubBuffer(std::span<unsigned char> d)
            : data(d)
        {
        }

    private:
        std::span<unsigned char> data;
    };


    class ParsingDataBuffer {
    public:
        ParsingDataBuffer(CharDataVector data);
        unsigned char GetNextByte();
        unsigned char GetCurrentByte();
        unsigned char GetNextByteNotEOF();
        unsigned short GetNextTwoOctets();
        unsigned int GetNextFourOctets();
        bool Skip(unsigned long packet_length);

        ParsingDataSubBuffer GetRange(size_t length);
        ParsingDataSubBuffer GetRange(size_t start_pos, size_t last_pos);
        ParsingDataSubBuffer GetRawData();

        CharDataVector GetRangeOld(size_t length);
        CharDataVector GetRangeOld(size_t start_pos, size_t last_pos);
        CharDataVector GetRawDataOld();

        bool HasNextByte();
        void ResetCurrentPosition();

        bool IsEmpty() { return data.empty(); }
        size_t Length() { return data.size(); }
        size_t RestLength() { return data.size() - currentPosition; };
        size_t CurrentPosition() const { return currentPosition; };

    private:
        CharDataVector data;
        size_t currentPosition;
    };
}


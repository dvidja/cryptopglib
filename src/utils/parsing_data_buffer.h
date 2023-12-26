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
    union DataHandler {
        std::vector<unsigned char> owned_data;
        std::span<unsigned char> unowned_data;
        DataHandler(std::vector<unsigned char> data)
            : owned_data(std::move(data)){
        }
        DataHandler(std::span<unsigned char> data)
                : unowned_data(data){
        }
        ~DataHandler() {

        }
    };

    class ParsingDataBuffer {
    public:
        ParsingDataBuffer(CharDataVector data);
        ParsingDataBuffer(std::span<unsigned char> data);
        unsigned char GetNextByte();
        unsigned char GetCurrentByte();
        unsigned char GetNextByteNotEOF();
        unsigned short GetNextTwoOctets();
        unsigned int GetNextFourOctets();
        bool Skip(unsigned long packet_length);

        ParsingDataBuffer GetRange(size_t length);
        ParsingDataBuffer GetRange(size_t start_pos, size_t last_pos);
        ParsingDataBuffer GetRawData();

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
        size_t currentPosition;
        std::vector<unsigned char> data;

        DataHandler dataHandler;
    };
}


//
//  DataBuffer.h
//  cryptopg
//
//  Created by Anton Sarychev on 14.4.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_DataBuffer_
#define cryptopg_DataBuffer_

#include <iostream>

#include "../pgp_data/pgp_data_types.h"

namespace cryptopglib {

    class ParsingDataBuffer {
    public:
        ParsingDataBuffer(CharDataVector data);
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

        bool IsEmpty() { return data.empty(); }
        size_t Length() { return data.size(); }
        size_t RestLength() { return data.size() - currentPosition; };
        size_t CurrentPosition() const { return currentPosition; };

    private:
        CharDataVector data;
        size_t currentPosition;
    };
}

#endif /* cryptopg_DataBuffer_ */

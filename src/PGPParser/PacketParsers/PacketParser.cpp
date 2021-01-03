//
//  PacketParser.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 10.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//


#include "PacketParser.h"


int GetPacketLengthForPartialContent(DataBuffer& data_buffer, bool& partial)
{
    char hdr[8]; // ????
    int hdrlen = 0;
    int data_part_length = 0;
    
    int c = data_buffer.GetNextByte();
    
    if (c == -1)
    {
        // TODO : handle error
        return 0;
    }
    
    hdr[hdrlen++] = c;
    if (c < 192)
    {
        partial = false;
        data_part_length = c;
    }
    else if (c < 224)
    {
        partial = false;
        data_part_length = (c - 192) * 256;
        
        if ((c = data_buffer.GetNextByte()) == -1)
        {
            // TODO : handle error
            return 0;
        }
        
        hdr[hdrlen++] = c;
        data_part_length += c + 192;
    }
    else if (c == 255)
    {
        partial = false;
        data_part_length = (hdr[hdrlen++] = data_buffer.GetNextByteNotEOF()) << 24;
        data_part_length |= (hdr[hdrlen++] = data_buffer.GetNextByteNotEOF()) << 16;
        data_part_length |= (hdr[hdrlen++] = data_buffer.GetNextByteNotEOF()) << 8;
        
        if ((c = data_buffer.GetNextByte()) == -1)
        {
            //TODO: handle error
            return 0;
        }
        
        data_part_length |= (hdr[hdrlen++] = c);
    }
    else
    {
        partial = true;
        data_part_length = 1 << (c & 0x1f);
    }
    
    return data_part_length;
}

//
//  LiteralDataPacketParser.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 11.8.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "literal_data_packet_parser.h"

#include "../../pgp_data/packets/literal_data_packet.h"


LiteralDataPacket* LiteralDataPacketParser::Parse(DataBuffer& data_buffer, bool partial, int c)
{
    if (partial)
    {
        return ParsePartial(data_buffer, c);
    }
    
    LiteralDataPacket* packet = new LiteralDataPacket();
    
    data_buffer.GetNextByte();
    
    int file_name_length = data_buffer.GetNextByte();
    if(file_name_length != 0)
    {
        packet->SetFileName(data_buffer.GetRange(file_name_length));
    }

    data_buffer.GetNextFourOctets();
    
    CharDataVector data = data_buffer.GetRange(data_buffer.rest_length());
        
    packet->SetData(data);
         
    return packet;
}

LiteralDataPacket* LiteralDataPacketParser::ParsePartial(DataBuffer& data_buffer, int c)
{
    LiteralDataPacket* packet = new LiteralDataPacket();
    bool partial = true;
    int data_part_length = 1 << (c & 0x1f);
    size_t start_position = data_buffer.current_position();
    
    if (data_part_length >= 1)
    {
        data_buffer.GetNextByte(); // data formated not used
        data_part_length--;
    }
    
    if (data_part_length == 0)
    {
        data_part_length = GetPacketLengthForPartialContent(data_buffer, partial);
        start_position = data_buffer.current_position();
    }
    
    int file_name_length = data_buffer.GetNextByte();
    data_part_length--;
    if (file_name_length != 0)
    {
        if (data_part_length >= file_name_length)
        {
            packet->SetFileName(data_buffer.GetRange(file_name_length));
            data_part_length -= file_name_length;
        }
        else
        {
            //TODO: !!!!!
            return nullptr;
        }
    }
    
    if (data_part_length == 0)
    {
        data_part_length = GetPacketLengthForPartialContent(data_buffer, partial);
        start_position = data_buffer.current_position();
    }
    
    if (data_part_length >= 4)
    {
        data_buffer.GetNextFourOctets(); /// 4 zero or time
        data_part_length -= 4;
    }

    if (data_part_length == 0)
    {
        data_part_length = GetPacketLengthForPartialContent(data_buffer, partial);
        start_position = data_buffer.current_position();
    }
    
    //data_part_length -= (data_buffer.current_position() - start_position);
    
    CharDataVector result_data;
    
    do
    {
        CharDataVector temp_data(data_buffer.GetRange(data_part_length));
        
        result_data.insert(result_data.end(), temp_data.begin(), temp_data.end());
        
        if (!partial)
        {
            packet->SetData(result_data);
            return packet;
        }
        
        data_part_length = GetPacketLengthForPartialContent(data_buffer, partial);
        if (data_part_length == 0)
        {
            packet->SetData(result_data);
            return packet;
        }
    }
    while (data_buffer.rest_length() != 0);
    
    
    
    return nullptr;
}
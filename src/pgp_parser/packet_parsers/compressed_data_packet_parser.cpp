//
//  CompressedDataPacketParser.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 11.8.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "compressed_data_packet_parser.h"
#include "../../crypto/compression_algorithms.h"

namespace cryptopglib::pgp_parser::packet_parsers {
    CompressedDataPacket *CompressedDataPacketParser::Parse(DataBuffer &data_buffer, bool partial, int c) {
        CompressionAlgorithms compress_algo = static_cast<CompressionAlgorithms>(data_buffer.GetNextByte());

        CompressedDataPacket *packet = new CompressedDataPacket;
        packet->SetCompressAlgorithm(compress_algo);
        if (partial) {
            CharDataVector result_data;
            int data_part_length = 0;

            if (c != 0) {
                data_part_length = 1 << (c & 0x1f);
                data_part_length--;
            } else {
                packet->SetData(data_buffer.GetRange(data_buffer.rest_length()));
                return packet;
            }

            do {
                CharDataVector temp_data(data_buffer.GetRange(data_part_length));

                result_data.insert(result_data.end(), temp_data.begin(), temp_data.end());

                if (!partial) {
                    packet->SetData(result_data);
                    return packet;
                }

                data_part_length = GetPacketLengthForPartialContent(data_buffer, partial);

                if (data_part_length == 0) {
                    packet->SetData(result_data);
                    return packet;
                }
            } while (data_buffer.rest_length() != 0);
        } else {
            packet->SetData(data_buffer.GetRange(data_buffer.rest_length()));
        }

        return packet;
    }
}

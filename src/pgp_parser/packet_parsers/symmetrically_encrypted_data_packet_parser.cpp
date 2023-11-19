//
//  SymmetricallyEncryptedDataPacketParser.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 10.5.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "symmetrically_encrypted_data_packet_parser.h"
#include "../../pgp_data/packets/symmetrically_encrypted_data_packet.h"

namespace cryptopglib::pgp_parser::packet_parsers {
    SymmetricallyEncryptedDataPacketParser::SymmetricallyEncryptedDataPacketParser(bool mdc)
            : mdc_(mdc) {
    }

    PGPPacket *SymmetricallyEncryptedDataPacketParser::Parse(DataBuffer &data_buffer, bool partial, int c) {
        if (mdc_) {
            int version = data_buffer.GetNextByte();
            if (version != 1) {
                // TODO: handle error
                return nullptr;
            }
        }

        if (data_buffer.rest_length() < 10) {
            return nullptr;
        }

        if (partial) {
            pgp_data::packets::SymmetricallyEncryptedDataPacket *packet = new pgp_data::packets::SymmetricallyEncryptedDataPacket
                    (mdc_ ? PT_SYMMETRIC_ENCRYTPED_AND_INTEGRITY_PROTECTED_DATA_PACKET
                          : PT_SYMMETRICALLY_ENCRYPTED_DATA_PACKET);

            int data_part_length = 0;
            CharDataVector result_data;

            if (c != 0) {
                data_part_length = 1 << (c & 0x1f);
                data_part_length--;
            } else {
                CharDataVector encrypted_data = data_buffer.GetRange(data_buffer.rest_length());
                packet->SetEncryptedData(encrypted_data);

                return packet;
            }

            do {
                CharDataVector temp_data(data_buffer.GetRange(data_part_length));
                result_data.insert(result_data.end(), temp_data.begin(), temp_data.end());

                if (!partial) {
                    packet->SetEncryptedData(result_data);
                    return packet;
                }

                data_part_length = GetPacketLengthForPartialContent(data_buffer, partial);

                if (data_part_length == 0) {
                    packet->SetEncryptedData(result_data);
                    return packet;
                }
            } while (data_buffer.rest_length() != 0);
        } else {
            pgp_data::packets::SymmetricallyEncryptedDataPacket *packet = new pgp_data::packets::SymmetricallyEncryptedDataPacket
                    (mdc_ ? PT_SYMMETRIC_ENCRYTPED_AND_INTEGRITY_PROTECTED_DATA_PACKET
                          : PT_SYMMETRICALLY_ENCRYPTED_DATA_PACKET);

            CharDataVector encrypted_data = data_buffer.GetRange(data_buffer.rest_length());
            packet->SetEncryptedData(encrypted_data);

            return packet;
        }

        return nullptr;
    }
}
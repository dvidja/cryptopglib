//
//  MarkerPacket.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "marker_packet.h"

namespace cryptopglib::pgp_data::packets {
    MarkerPacket::MarkerPacket()
            : PGPPacket(PacketType::kMarkerPacket) {

    }

    void MarkerPacket::SetData(CharDataVector &data) {
        data_.assign(data.begin(), data.end());
    }

    CharDataVector &MarkerPacket::GetData() {
        return data_;
    }

    bool MarkerPacket::GetRawData(CharDataVector &data) {
        CharDataVector temp_data(data_);
        data.insert(data.end(), temp_data.begin(), temp_data.end());

        return true;
    }

    bool MarkerPacket::GetBinaryData(CharDataVector &data) {
        CharDataVector temp_data;

        if (!GetRawData(temp_data)) {
            return false;
        }

        ///////////////////////////////
        unsigned char c = 0;
        c ^= 0x80;
        c ^= 0x40;
        c ^= (unsigned char)GetPacketType();
        data.push_back(c);

        if (temp_data.size() < 192) {
            data.push_back(temp_data.size());
        } else if (temp_data.size() < 8384) {
            int length = static_cast<int>(temp_data.size()) - 192;
            data.push_back((length / 256) + 192);
            data.push_back(length % 256);
        } else {
            int length = static_cast<int>(temp_data.size());
            data.push_back(0xff);
            data.push_back((length >> 24) & 0xff);
            data.push_back((length >> 16) & 0xff);
            data.push_back((length >> 8) & 0xff);
            data.push_back(length & 0xff);
        }

        data.insert(data.end(), temp_data.begin(), temp_data.end());

        return true;
    }
}

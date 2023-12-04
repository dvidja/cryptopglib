//
//  UserIDPacket.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 2.7.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "user_id_packet.h"

#include <cmath>

namespace cryptopglib::pgp_data::packets {
    UserIDPacket::UserIDPacket()
            : PGPPacket(PacketType::kUserIDPacket) {

    }

    void UserIDPacket::SetUserID(const CharDataVector &user_id) {
        user_id_.clear();
        user_id_.append(user_id.begin(), user_id.end());
    }

    std::string UserIDPacket::GetUserID() {
        return user_id_;
    }

    bool UserIDPacket::GetRawData(CharDataVector &data) {
        CharDataVector temp_data;
        temp_data.insert(temp_data.end(), user_id_.begin(), user_id_.end());

        data.insert(data.end(), temp_data.begin(), temp_data.end());

        return true;
    }

    bool UserIDPacket::GetBinaryData(CharDataVector &data) {
        CharDataVector temp_data;
        if (!GetRawData(temp_data)) {
            return false;
        }

        ///////////////////////////////
        unsigned char c = 0;
        c ^= 0x80;

        // commented old format packet
        /*c ^= GetPacketType() << 2;

        double t = temp_data.size();
        int num_bits = log2(t) + 1;

        int num_octets = num_bits / 8 + 1;

        if (num_octets == 1)
        {
            data.push_back(c);
            data.push_back(user_id_.size() & 0xFF);
        }
        else if (num_octets == 2)
        {
            c ^= 1;
            data.push_back(c);
            data.push_back((user_id_.size() >> 8) & 0xFF);
            data.push_back(user_id_.size() & 0xFF);

        }
        else if ((num_octets == 3) && (num_octets == 4))
        {
            c ^= 2;
            data.push_back(c);
            data.push_back((user_id_.size() >> 24) & 0xFF);
            data.push_back((user_id_.size() >> 16) & 0xFF);
            data.push_back((user_id_.size() >> 8) & 0xFF);
            data.push_back(user_id_.size() & 0xFF);

        }

        data.insert(data.end(), temp_data.begin(), temp_data.end());*/

        // new format sont work
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

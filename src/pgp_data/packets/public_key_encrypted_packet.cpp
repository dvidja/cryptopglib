//
//  PublicKeyEncryptedPacket.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 23.6.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "public_key_encrypted_packet.h"

namespace cryptopglib::pgp_data::packets {
    PublicKeyEncryptedPacket::PublicKeyEncryptedPacket()
            : PGPPacket(PT_PUBLIC_KEY_ENCRYPTED_PACKET) {

    }

    int PublicKeyEncryptedPacket::GetVersion() {
        return 3;
    }

    KeyIDData PublicKeyEncryptedPacket::GetKeyID() {
        return key_id_;
    }

    PublicKeyAlgorithms PublicKeyEncryptedPacket::GetPublicKeyAlgorithm() {
        return public_key_algorithm_;
    }

    CharDataVector PublicKeyEncryptedPacket::GetMPI(size_t index) {
        if ((mpis_.size() != 0) && (index < mpis_.size())) {
            return mpis_[index];
        }

        return CharDataVector();
    }

    void PublicKeyEncryptedPacket::SetKeyID(KeyIDData &key_id) {
        key_id_.resize(key_id.size());
        std::move(key_id.begin(), key_id.end(), key_id_.begin());
    }

    void PublicKeyEncryptedPacket::SetPublicKeyAlgorithm(PublicKeyAlgorithms algo) {
        public_key_algorithm_ = algo;
    }

    void PublicKeyEncryptedPacket::AddMPI(CharDataVector mpi_data) {
        mpis_.push_back(mpi_data);
    }

    bool PublicKeyEncryptedPacket::GetRawData(CharDataVector &data) {
        CharDataVector temp_data;

        temp_data.push_back(3); //packet version

        KeyIDData key_id(GetKeyID());
        if (key_id.size() == 2) {
            CharDataVector key_id_data;
            pgp_data::GetKeyIDData(key_id, key_id_data);
            temp_data.insert(temp_data.end(), key_id_data.begin(), key_id_data.end());
        } else {
            data.clear();
            return false;
        }

        temp_data.push_back(GetPublicKeyAlgorithm());

        for (auto iter = mpis_.begin(); iter != mpis_.end(); ++iter) {
            if ((GetPublicKeyAlgorithm() != PKA_DSA) && (GetPublicKeyAlgorithm() != PKA_ELGAMAL)) {

                int mpi_size = static_cast<int>(iter->size());
                mpi_size *= 8;

                double t = (*iter)[0];
                int bits = pgp_data::log2(t) + 1;
                int delta = 8 - bits;
                mpi_size -= delta;

                temp_data.push_back((mpi_size >> 8) & 0xFF);
                temp_data.push_back(mpi_size & 0xFF);
            }
            temp_data.insert(temp_data.end(), iter->begin(), iter->end());
        }

        data.insert(data.end(), temp_data.begin(), temp_data.end());

        return true;
    }

    bool PublicKeyEncryptedPacket::GetBinaryData(CharDataVector &data) {
        CharDataVector temp_data;

        if (!GetRawData(temp_data)) {
            return false;
        }

        ///////////////////////////////
        unsigned char c = 0;
        c ^= 0x80;
        c ^= 0x40;
        c ^= GetPacketType();
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
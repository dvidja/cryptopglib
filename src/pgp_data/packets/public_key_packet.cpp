//
//  RSAPublicKeyPacket.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 26.5.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "public_key_packet.h"

namespace
{
    using namespace cryptopglib;

    void PushMPIDataToVector(const std::vector<CharDataVector>& mpis, CharDataVector& data)
    {
        for (auto iter = mpis.begin(); iter != mpis.end(); ++iter)
        {
            int mpi_size = static_cast<int>(iter->size());
            mpi_size *= 8;
            
            double t = (*iter)[0];
            int bits = pgp_data::log2(t) + 1;
            int delta = 8 - bits;
            mpi_size -= delta;
            
            data.push_back((mpi_size >> 8) & 0xFF);
            data.push_back(mpi_size & 0xFF);
            data.insert(data.end(), iter->begin(), iter->end());
        }

    }
}

namespace cryptopglib::pgp_data::packets {
    PublicKeyPacket::PublicKeyPacket(int key_version, bool is_subkey)
            : PGPPacket(is_subkey ? PacketType::kPublicSubkeyPacket : PacketType::kPublicKeyPacket), key_version_(key_version),
              expired_time_(0) {

    }

    PublicKeyPacket::PublicKeyPacket(PublicKeyPacket &public_key_packet)
            : PGPPacket(public_key_packet.GetPacketType()) {
        key_version_ = public_key_packet.GetKeyVersion();
        timestamp_ = public_key_packet.GetTimestamp();
        expired_time_ = public_key_packet.GetKeyExpiredTime();
        algorithm_ = public_key_packet.GetPublicKeyAlgorithm();
        mpis_.assign(public_key_packet.mpis_.begin(), public_key_packet.mpis_.end());
        key_id_.assign(public_key_packet.key_id_.begin(), public_key_packet.key_id_.end());
        fingerprint_.assign(public_key_packet.fingerprint_);
    }

    PublicKeyPacket::~PublicKeyPacket() {

    }

    int PublicKeyPacket::GetKeyVersion() {
        return key_version_;
    }

    void PublicKeyPacket::SetTimestamp(unsigned int timestamp) {
        timestamp_ = timestamp;
    }

    unsigned int PublicKeyPacket::GetTimestamp() {
        return timestamp_;
    }

    void PublicKeyPacket::SetKeyExpiredTime(unsigned int expired_time) {
        expired_time_ = expired_time;
    }

    unsigned int PublicKeyPacket::GetKeyExpiredTime() {
        return expired_time_;
    }

    void PublicKeyPacket::SetPublicKeyAlgorithm(PublicKeyAlgorithms algo) {
        algorithm_ = algo;
    }

    PublicKeyAlgorithms PublicKeyPacket::GetPublicKeyAlgorithm() {
        return algorithm_;
    }

    void PublicKeyPacket::AddMPI(CharDataVector mpi_data) {
        mpis_.push_back(mpi_data);
    }

    CharDataVector PublicKeyPacket::GetMPI(size_t index) {
        if ((mpis_.size() != 0) && (index < mpis_.size())) {
            return mpis_[index];
        }

        return CharDataVector();
    }

    void PublicKeyPacket::SetKeyID(KeyIDData &key_id) {
        key_id_.resize(key_id.size());
        std::move(key_id.begin(), key_id.end(), key_id_.begin());
    }

    KeyIDData PublicKeyPacket::GetKeyID() {
        return key_id_;
    }

    void PublicKeyPacket::SetFingerprint(std::string fingerprint) {
        fingerprint_.assign(fingerprint);
    }

    std::string PublicKeyPacket::GetFingerprint() {
        return fingerprint_;
    }

    void PublicKeyPacket::SetKeySize(int size) {
        key_size_ = size;
    }

    int PublicKeyPacket::GetKeySize() {
        return key_size_;
    }


    bool PublicKeyPacket::GetRawData(CharDataVector &data) {
        CharDataVector temp_data;

        temp_data.push_back(GetKeyVersion());

        unsigned int creation_time = GetTimestamp();
        temp_data.push_back((creation_time >> 24) & 0xFF);
        temp_data.push_back((creation_time >> 16) & 0xFF);
        temp_data.push_back((creation_time >> 8) & 0xFF);
        temp_data.push_back(creation_time & 0xFF);


        if (GetKeyVersion() == 3) {
            temp_data.push_back(0);
            temp_data.push_back(0);
        }

        temp_data.push_back(GetPublicKeyAlgorithm());

        PushMPIDataToVector(mpis_, temp_data);

        data.assign(temp_data.begin(), temp_data.end());

        return true;
    }

    bool PublicKeyPacket::GetBinaryData(CharDataVector &data) {
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
//
//  OnePassSignaturePacket.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "one_pass_signature_packet.h"

namespace cryptopglib::pgp_data::packets {
    OnePassSignaturePacket::OnePassSignaturePacket()
            : PGPPacket(PacketType::kOnePassSignaturePacket) {

    }

    OnePassSignaturePacket::OnePassSignaturePacket(SignaturePacketPtr signature_packet_ptr)
            : PGPPacket(PacketType::kOnePassSignaturePacket), version_(3),
              signature_type_(signature_packet_ptr->GetSignatureType()),
              hash_algo_(signature_packet_ptr->GetHashAlgorithm()),
              pub_key_algo_(signature_packet_ptr->GetPublicKeyAlgorithm()), nested_(1) {
        SetKeyID(signature_packet_ptr->GetKeyID());
    }

    void OnePassSignaturePacket::SetVersion(const int version) {
        version_ = version;
    }

    void OnePassSignaturePacket::SetSignatureType(const int signature_type) {
        signature_type_ = signature_type;
    }

    void OnePassSignaturePacket::SetHashAlgorithm(HashAlgorithms hash_algo) {
        hash_algo_ = hash_algo;
    }

    void OnePassSignaturePacket::SetPublicKeyAlgorithm(const PublicKeyAlgorithms pub_key_algo) {
        pub_key_algo_ = pub_key_algo;
    }

    void OnePassSignaturePacket::SetKeyID(const KeyIDData &key_id) {
        key_id_.assign(key_id.begin(), key_id.end());
    }

    void OnePassSignaturePacket::SetNested(const int nested) {
        nested_ = nested;
    }

    int OnePassSignaturePacket::GetVersion() {
        return version_;
    }

    int OnePassSignaturePacket::GetSignatureType() {
        return signature_type_;
    }

    HashAlgorithms OnePassSignaturePacket::GetHashAlgorithm() {
        return hash_algo_;
    }

    PublicKeyAlgorithms OnePassSignaturePacket::GetPublicKeyAlgorithm() {
        return pub_key_algo_;
    }

    KeyIDData &OnePassSignaturePacket::GetKeyID() {
        return key_id_;
    }

    int OnePassSignaturePacket::GetNested() {
        return nested_;
    }

    bool OnePassSignaturePacket::GetRawData(CharDataVector &data) {
        CharDataVector temp_data;

        temp_data.push_back(GetVersion());
        temp_data.push_back(GetSignatureType());
        temp_data.push_back((unsigned char)GetHashAlgorithm());
        temp_data.push_back(GetPublicKeyAlgorithm());

        CharDataVector key_id_data;
        pgp_data::GetKeyIDData(GetKeyID(), key_id_data);
        temp_data.insert(temp_data.end(), key_id_data.begin(), key_id_data.end());

        temp_data.push_back(GetNested());

        data.assign(temp_data.begin(), temp_data.end());

        return true;
    }

    bool OnePassSignaturePacket::GetBinaryData(CharDataVector &data) {
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

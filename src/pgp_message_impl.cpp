//
//  PGPMessageImpl.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 22.4.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "pgp_message_impl.h"

#include "utils/base64.h"

namespace cryptopglib {
    PGPMessageImpl::PGPMessageImpl() {
    }

    PGPMessageImpl::~PGPMessageImpl() {
    }

    PGPMessageType PGPMessageImpl::GetMessageType() {
        return message_type_;
    }

    std::string PGPMessageImpl::GetPlainText() {
        return plain_text_;
    }

    std::string PGPMessageImpl::GetBase64Data() {
        return data_;
    }

    std::string PGPMessageImpl::GetCRC() {
        return crc_;
    }

    CharDataVector PGPMessageImpl::GetRawData() {
        return utils::Base64Decode(data_);
    }

    void PGPMessageImpl::SetMessageType(const PGPMessageType message_type) {
        message_type_ = message_type;
    }

    void PGPMessageImpl::SetPlainText(const std::string &plain_text) {
        plain_text_ = plain_text;
    }

    void PGPMessageImpl::SetBase64Data(const std::string &data) {
        data_ = data;
    }

    void PGPMessageImpl::SetCRC(const std::string &crc) {
        crc_ = crc;
    }

    void PGPMessageImpl::AddArmorHeaderValue(const std::string &key, const std::string &value) {
        armor_header_map_[key] = value;
    }

    void PGPMessageImpl::AddPlainText(const std::string &text) {
        plain_text_.append(text);
    }

    void PGPMessageImpl::AddData(const std::string &data) {
        data_.append(data);
    }

    void PGPMessageImpl::SetPackets(PGPPacketsArray &packets) {
        packets_.assign(packets.begin(), packets.end());
        if (packets.size() > 0) {
            switch (packets[0]->GetPacketType()) {
                case PacketType::kPublicKeyPacket:
                    message_type_ = PGPMessageType::kPublicKey;
                    break;
                case PacketType::kSecretKeyPacket:
                    message_type_ = PGPMessageType::kPrivateKey;
                    break;
                case PacketType::kSignaturePacket:
                    message_type_ = PGPMessageType::kSignedMessage;
                    break;
                default:
                    break;
            }
        }
    }

    const PGPPacketsArray &PGPMessageImpl::GetPackets() {
        return packets_;
    }

    void PGPMessageImpl::AddPacket(std::shared_ptr<PGPPacket> packet) {
        packets_.push_back(packet);
    }
}




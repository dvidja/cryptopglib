//
//  PGPMessageImpl.h
//  cryptopg
//
//  Created by Anton Sarychev on 22.4.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#pragma once

#include <iostream>
#include <vector>

#include "cryptopglib/pgp_message.h"
#include "pgp_data/pgp_packet.h"

namespace cryptopglib {
    using namespace pgp_data;

    class PGPMessageImpl : public PGPMessage {
    public:
        PGPMessageImpl();

        ~PGPMessageImpl() override;

        PGPMessageType GetMessageType() override;

        std::string GetPlainText() override;

        std::string GetBase64Data() override;

        std::string GetCRC() override;

        CharDataVector GetRawData();

        void SetMessageType(PGPMessageType message_type);

        void SetPlainText(const std::string &plain_text);

        void SetBase64Data(const std::string &data);

        void SetCRC(const std::string &crc);

        void AddArmorHeaderValue(const std::string &key, const std::string &value);

        void AddPlainText(const std::string &text);

        void AddData(const std::string &data);

        void SetPackets(PGPPacketsArray &packets);

        const PGPPacketsArray &GetPackets();

        void AddPacket(std::shared_ptr<PGPPacket> packet);

    private:

        PGPMessageType message_type_;
        std::string plain_text_; // used for plain text
        std::string data_;
        std::string crc_;
        ArmorHeadersMap armor_header_map_;

        KeyIDData key_id_;
        PGPPacketsArray packets_;
    };

    typedef std::shared_ptr<PGPMessageImpl> PGPMessagePtr;
}


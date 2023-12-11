//
//  PublicKeyPacketParser.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 1.5.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "public_key_packet_parser.h"

#include "../../crypto/hash_algorithm.h"

#include <sstream>

namespace
{
    using cryptopglib::DataBuffer;
    size_t GetMPIDataLength(DataBuffer& data_buffer)
    {
        int l = data_buffer.GetNextTwoOctets();
        l = (l + 7) / 8;

        return l;
    }
}

namespace cryptopglib::pgp_parser::packet_parsers {
    PublicKeyPacket *PublicKeyPacketParser::Parse(DataBuffer &data_buffer, bool partial, int c) {
        bool is_v4 = false;

        int version = data_buffer.GetNextByteNotEOF();

        if (version == '#') {
            // TODO: read comment

            data_buffer.Skip(data_buffer.RestLength());
            return nullptr;
        }

        if (version == 4) {
            is_v4 = true;
        } else if (version != 2 && version != 3) {
            // TODO: handle error
            return nullptr;
        }

        if (data_buffer.RestLength() < 11) {
            // TODO: handle error
            return nullptr;
        }

        auto *packet = new PublicKeyPacket(version);

        unsigned int timestamp = data_buffer.GetNextFourOctets();
        packet->SetTimestamp(timestamp);

        if (!is_v4) {
            unsigned short expired_days = data_buffer.GetNextTwoOctets();
            unsigned int expired_seconds = expired_days * 24 * 60 * 60;
            packet->SetKeyExpiredTime(packet->GetTimestamp() + expired_seconds);
        }

        auto algorithm = (PublicKeyAlgorithms) data_buffer.GetNextByteNotEOF();

        packet->SetPublicKeyAlgorithm(algorithm);

        int rest_length = data_buffer.RestLength();

        switch (algorithm) {
            case kRSA:
            case kRSAEncryptOnly:
            case kRSASignOnly: {
                size_t length = GetMPIDataLength(data_buffer);
                packet->AddMPI(data_buffer.GetRange(length));
                packet->SetKeySize(length * 8);

                length = GetMPIDataLength(data_buffer);
                packet->AddMPI(data_buffer.GetRange(length));
            }

                break;

            case kElgamal: {
                size_t length = GetMPIDataLength(data_buffer);
                packet->AddMPI(data_buffer.GetRange(length));
                packet->SetKeySize(length * 8);

                length = GetMPIDataLength(data_buffer);
                packet->AddMPI(data_buffer.GetRange(length));

                length = GetMPIDataLength(data_buffer);
                packet->AddMPI(data_buffer.GetRange(length));
            }

                break;

            case kDSA: {
                size_t length = GetMPIDataLength(data_buffer);
                packet->AddMPI(data_buffer.GetRange(length));
                packet->SetKeySize(length * 8);

                length = GetMPIDataLength(data_buffer);
                packet->AddMPI(data_buffer.GetRange(length));

                length = GetMPIDataLength(data_buffer);
                packet->AddMPI(data_buffer.GetRange(length));

                length = GetMPIDataLength(data_buffer);
                packet->AddMPI(data_buffer.GetRange(length));
            }

                break;

            default:
                return nullptr;
        }

        CharDataVector fingerprint;
        fingerprint.push_back(0x99);

        size_t length = data_buffer.CurrentPosition();

        int a1 = length & 0xFF;
        int a2 = (length >> 8) & 0xFF;
        fingerprint.push_back(a2);
        fingerprint.push_back(a1);
        CharDataVector tmp_data = data_buffer.GetRawData();
        fingerprint.insert(fingerprint.end(), tmp_data.begin(), tmp_data.begin() + length);

        CharDataVector hash;
        crypto::Sha1 sha1;
        if (!sha1.Hash(fingerprint, hash)) {
            return nullptr;
        }

        std::string fingerprint_str;

        DataBuffer hash_data(hash);

        for (int i = 0; i < hash.size() / 2; ++i) {
            unsigned short t = hash_data.GetNextTwoOctets();
            std::ostringstream temp;
            temp << std::hex << t;
            std::string temp_str = temp.str();
            if (temp_str.length() != 4) {
                for (int i = temp_str.length(); i < 4; ++i) {
                    temp_str.insert(0, "0");
                }
            }

            fingerprint_str += " " + temp_str;
        }

        fingerprint_str.erase(fingerprint_str.begin(), fingerprint_str.begin() + 1);

        size_t hash_size = hash.size();
        unsigned int id1;
        id1 = hash[hash_size - 8] << 24;
        id1 |= hash[hash_size - 7] << 16;
        id1 |= hash[hash_size - 6] << 8;
        id1 |= hash[hash_size - 5];

        unsigned int id2;
        id2 = hash[hash_size - 4] << 24;
        id2 |= hash[hash_size - 3] << 16;
        id2 |= hash[hash_size - 2] << 8;
        id2 |= hash[hash_size - 1];

        KeyIDData key_id = {id1, id2};

        packet->SetKeyID(key_id);
        packet->SetFingerprint(fingerprint_str);

        return packet;
    }
}
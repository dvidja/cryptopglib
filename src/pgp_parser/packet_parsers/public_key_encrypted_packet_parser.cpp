//
//  PublicKeyEnctyptedPacketParser.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 1.5.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "public_key_encrypted_packet_parser.h"
#include "../../crypto/public_key_algorithms.h"
#include "../../pgp_data/pgp_data_types.h"

namespace cryptopglib::pgp_parser::packet_parsers {
    PublicKeyEncryptedPacket *PublicKeyEncryptedPacketParser::Parse(DataBuffer &data_buffer, bool partial, int c) {
        if (data_buffer.rest_length() < 12) {
            //TODO: handle error
            // skip packet
            return nullptr;
        }

        int version = data_buffer.GetNextByteNotEOF();

        if (version != 3) {
            // TODO: handle error
            // current verion must be 3 !!!
            return nullptr;
        }

        PublicKeyEncryptedPacket *packet = new PublicKeyEncryptedPacket();

        KeyIDData key_id(2);
        key_id[0] = data_buffer.GetNextFourOctets();
        key_id[1] = data_buffer.GetNextFourOctets();
        packet->SetKeyID(key_id);

        PublicKeyAlgorithms public_key_algo = static_cast<PublicKeyAlgorithms>(data_buffer.GetNextByteNotEOF());
        packet->SetPublicKeyAlgorithm(public_key_algo);

        switch (public_key_algo) {
            case kRSA:
            case kRSAEncryptOnly: {
                {
                    int l = data_buffer.GetNextTwoOctets();
                    l = (l + 7) / 8;

                    CharDataVector mpi_data = data_buffer.GetRange(l);
                    packet->AddMPI(mpi_data);
                }
            }

                break;

            case kElgamal:
            case kDSA: {
                CharDataVector mpis = data_buffer.GetRange(data_buffer.rest_length());
                packet->AddMPI(mpis);

                break;
            }

            default:
                return nullptr;
        }


        return packet;
    }
}

//
//  SignaturePacketParser.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 1.5.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "signature_packet_parser.h"
#include "../../crypto/public_key_algorithms.h"
#include "../../crypto/hash_algorithm.h"
#include "../../crypto/symmetric_key_algorithm.h"
#include "../../crypto/compression_algorithms.h"
#include "cryptopglib/symmetric_key_algorithms.h"

namespace cryptopglib::pgp_parser::packet_parsers {
    using namespace pgp_data::packets;
    SignaturePacket *SignaturePacketParser::Parse(ParsingDataBuffer &data_buffer, bool partial, int c) {
        if (data_buffer.RestLength() < 16) {
            //TODO : handle error
            return nullptr;
        }

        int version = data_buffer.GetNextByteNotEOF();

        if ((version < 2) || (version > 5)) {
            // TODO: handle error
            return nullptr;
        }

        if (version == 4) {
            return ParseV4Packet(data_buffer, partial);
        } else {
            return ParseV3Packet(data_buffer, partial);
        }

        return nullptr;
    }

    SignaturePacket *SignaturePacketParser::ParseV3Packet(ParsingDataBuffer &data_buffer, bool partial) {
        SignaturePacket *packet = new SignaturePacket(3);

        packet->SetExpiredSignatureTime(0);

        int md5_length = data_buffer.GetNextByteNotEOF();
        if (md5_length != 5) {
            //TODO: handle error
        }

        int signature_class = data_buffer.GetNextByteNotEOF();
        packet->SetSignatureType(signature_class);

        unsigned int creation_time = data_buffer.GetNextFourOctets();
        packet->SetCreationTime(creation_time);

        KeyIDData key_id(2);
        key_id[0] = data_buffer.GetNextFourOctets();
        key_id[1] = data_buffer.GetNextFourOctets();
        packet->SetKeyID(key_id);

        PublicKeyAlgorithms public_key_algorithm = static_cast<PublicKeyAlgorithms>(data_buffer.GetNextByteNotEOF());
        packet->SetPublicKeyAlgorithm(public_key_algorithm);

        HashAlgorithms digest_algorithm = static_cast<HashAlgorithms>(data_buffer.GetNextByteNotEOF());
        packet->SetHashAlgorithm(digest_algorithm);

        if (data_buffer.RestLength() < 5) {
            //TODO: handle error
            return nullptr;
        }

        std::vector<int> digest_start(2);
        digest_start[0] = data_buffer.GetNextByteNotEOF();
        digest_start[1] = data_buffer.GetNextByteNotEOF();

        packet->SetDigestStart(digest_start);

        switch (public_key_algorithm) {
            case kRSA:
            case kRSASignOnly: {
                int l = data_buffer.GetNextTwoOctets();
                l = (l + 7) / 8;

                CharDataVector mpi_data = data_buffer.GetRangeOld(l);
                packet->AddMPI(mpi_data);
            }
                return packet;

            case kDSA: {
                // !!! for DSA we read all data
                CharDataVector mpis = data_buffer.GetRangeOld(data_buffer.RestLength());
                packet->AddMPI(mpis);
            }
                return packet;

            default:
                break;
        }

        data_buffer.GetRangeOld(data_buffer.RestLength());

        return nullptr;
    }

    SignaturePacket *SignaturePacketParser::ParseV4Packet(ParsingDataBuffer &data_buffer, bool partial) {
        SignaturePacket *packet = new SignaturePacket(4);

        int signature_class = data_buffer.GetNextByteNotEOF();
        packet->SetSignatureType(signature_class);
        packet->SetExpiredSignatureTime(0);

        PublicKeyAlgorithms public_key_algorithm = static_cast<PublicKeyAlgorithms>(data_buffer.GetNextByteNotEOF());
        packet->SetPublicKeyAlgorithm(public_key_algorithm);

        HashAlgorithms digest_algorithm = static_cast<HashAlgorithms>(data_buffer.GetNextByteNotEOF());
        packet->SetHashAlgorithm(digest_algorithm);

        int n = data_buffer.GetNextTwoOctets();
        if (n > 10000) {
            // TODO: handle error "signature packet: hashed data too long;
            return nullptr;
        }
        if (n) {
            //Hashed subpacket data
            ParseSubPacket(data_buffer.GetRangeOld(n), packet, true);
        }

        n = data_buffer.GetNextTwoOctets();
        if (n > 10000) {
            //TODO: handle error "signature packet: unhashed data too long
            return nullptr;
        }
        if (n) {
            // Unhashed subpasket data
            ParseSubPacket(data_buffer.GetRangeOld(n), packet, false);
        }

        if (data_buffer.RestLength() < 5) {
            //TODO: handle error
            return nullptr;
        }

        std::vector<int> digest_start(2);
        digest_start[0] = data_buffer.GetNextByteNotEOF();
        digest_start[1] = data_buffer.GetNextByteNotEOF();

        packet->SetDigestStart(digest_start);

        switch (public_key_algorithm) {
            case kRSA: {
                int l = data_buffer.GetNextTwoOctets();
                l = (l + 7) / 8;

                CharDataVector mpi_data = data_buffer.GetRangeOld(l);
                packet->AddMPI(mpi_data);
            }
                return packet;

            case kDSA: {
                // !!! for DSA we read all data
                CharDataVector mpis = data_buffer.GetRangeOld(data_buffer.RestLength());
                packet->AddMPI(mpis);
            }
                return packet;

            default:
                break;
        }

        data_buffer.GetRangeOld(data_buffer.RestLength());

        return nullptr;
    }

    void SignaturePacketParser::ParseSubPacket(ParsingDataBuffer data_buffer, SignaturePacket *packet, bool hashed) {
        if (data_buffer.Length() < 2) {
            return;
        }

        int subpacket_length = 0;
        int n = data_buffer.GetNextByte();
        if (n < 192) {
            subpacket_length = n;
        }
        if ((n >= 192) && (n < 255)) {
            subpacket_length = ((n - 192) << 8) + data_buffer.GetNextByte() + 192;
        }
        if (n == 255) {
            subpacket_length = data_buffer.GetNextFourOctets();
        }

        SignatureSubPacketType subpacket_type = static_cast<SignatureSubPacketType>(data_buffer.GetNextByte());

        switch (subpacket_type) {
            case SST_ISSUER: {
                CharDataVector subpacket_data = data_buffer.GetRangeOld(subpacket_length - 1);
                if (subpacket_data.size() != 8) {
                    break;
                }

                KeyIDData key_id(2);
                key_id[0] = 0;
                key_id[1] = 0;

                key_id[0] = subpacket_data[0] << 24;
                key_id[0] |= subpacket_data[1] << 16;
                key_id[0] |= subpacket_data[2] << 8;
                key_id[0] |= subpacket_data[3];

                key_id[1] = subpacket_data[4] << 24;
                key_id[1] |= subpacket_data[5] << 16;
                key_id[1] |= subpacket_data[6] << 8;
                key_id[1] |= subpacket_data[7];

                packet->SetKeyID(key_id);
            }
                break;
            case SST_SIGNATURE_CREATION_TIME: {
                CharDataVector subpacket_data = data_buffer.GetRangeOld(subpacket_length - 1);
                if (subpacket_data.size() != 4) {
                    break;
                }

                unsigned int creation_time = 0;
                creation_time = subpacket_data[0] << 24;
                creation_time |= subpacket_data[1] << 16;
                creation_time |= subpacket_data[2] << 8;
                creation_time |= subpacket_data[3];

                packet->SetCreationTime(creation_time);
            }
                break;
            case SST_EMBEDDED_SIGNATURE: {
                ParsingDataBuffer subpacket_data(data_buffer.GetRangeOld(subpacket_length - 1));
                packet->AddSubPacketData(subpacket_type, subpacket_data.GetRawDataOld(), hashed);
                SignaturePacketParser embeded_signature_parser;
                embeded_signature_parser.Parse(subpacket_data, false, 0);
            }
                break;
            case SST_KEY_EXPIRATION_TIME: {
                ParsingDataBuffer subpacket_data(data_buffer.GetRangeOld(subpacket_length - 1));
                packet->AddSubPacketData(subpacket_type, subpacket_data.GetRawDataOld(), hashed);

                if (subpacket_data.Length() != 4) {
                    break;
                }

                unsigned int expired_time = subpacket_data.GetNextFourOctets();
                packet->SetExpiredKeyTime(expired_time);
            }
                break;
            case SST_SIGNATURE_EXPIRATION_TIME: {
                ParsingDataBuffer subpacket_data(data_buffer.GetRangeOld(subpacket_length - 1));
                packet->AddSubPacketData(subpacket_type, subpacket_data.GetRawDataOld(), hashed);

                if (subpacket_data.Length() != 4) {
                    break;
                }

                unsigned int expired_time = subpacket_data.GetNextFourOctets();
                packet->SetExpiredSignatureTime(expired_time);
            }
                break;
            case SST_PREFERRED_HASH_ALGO: {
                ParsingDataBuffer subpacket_data(data_buffer.GetRangeOld(subpacket_length - 1));
                packet->AddSubPacketData(subpacket_type, subpacket_data.GetRawDataOld(), hashed);

                std::vector<HashAlgorithms> prefered_hash_algo;
                for (int i = 0; i < subpacket_data.Length(); ++i) {
                    char t = subpacket_data.GetNextByte();
                    prefered_hash_algo.push_back(static_cast<HashAlgorithms>(t));
                }

                packet->SetPreferredHahAlgorithms(prefered_hash_algo);
            }
                break;
            case SST_PREFERRED_SYMMETRIC_ALGO: {
                ParsingDataBuffer subpacket_data(data_buffer.GetRangeOld(subpacket_length - 1));
                packet->AddSubPacketData(subpacket_type, subpacket_data.GetRawDataOld(), hashed);

                std::vector<SymmetricKeyAlgorithms> prefered_chiper_algo;
                for (int i = 0; i < subpacket_data.Length(); ++i) {
                    char t = subpacket_data.GetNextByte();
                    prefered_chiper_algo.push_back(static_cast<SymmetricKeyAlgorithms>(t));
                }

                packet->SetPreferredCipherAlgorithms(prefered_chiper_algo);
            }
                break;
            case SST_PREFERRED_COMPRESSION_ALGO: {
                ParsingDataBuffer subpacket_data(data_buffer.GetRangeOld(subpacket_length - 1));
                packet->AddSubPacketData(subpacket_type, subpacket_data.GetRawDataOld(), hashed);

                std::vector<CompressionAlgorithms> prefered_compression_algo;
                for (int i = 0; i < subpacket_data.Length(); ++i) {
                    char t = subpacket_data.GetNextByte();
                    prefered_compression_algo.push_back(static_cast<CompressionAlgorithms>(t));
                }

                packet->SetPreferredCompressionAlgorithms(prefered_compression_algo);
            }
                break;

            default:
                packet->AddSubPacketData(subpacket_type, data_buffer.GetRangeOld(subpacket_length - 1), hashed);
                break;
        }

        if (data_buffer.RestLength() != 0) {
            ParseSubPacket(data_buffer.GetRangeOld(data_buffer.RestLength()), packet, hashed);
        }
    }
}

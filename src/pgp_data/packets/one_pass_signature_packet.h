//
//  OnePassSignaturePacket.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_OnePassSignaturePacket_
#define cryptopg_OnePassSignaturePacket_

#include "../pgp_packet.h"
#include "../../crypto/hash_algorithm.h"
#include "../../crypto/public_key_algorithms.h"
#include "signature_packet.h"

namespace cryptopglib::pgp_data::packets {
    class OnePassSignaturePacket : public PGPPacket {
    public:
        OnePassSignaturePacket();

        explicit OnePassSignaturePacket(SignaturePacketPtr signature_packet_ptr);

        void SetVersion(int version = 3);

        void SetSignatureType(int signature_type);

        void SetHashAlgorithm(HashAlgorithms hash_algo);

        void SetPublicKeyAlgorithm(PublicKeyAlgorithms pub_key_algo);

        void SetKeyID(const KeyIDData &key_id);

        void SetNested(int nested);

        int GetVersion();

        int GetSignatureType();

        HashAlgorithms GetHashAlgorithm();

        PublicKeyAlgorithms GetPublicKeyAlgorithm();

        KeyIDData &GetKeyID();

        int GetNested();

        bool GetRawData(CharDataVector &data) override;

        bool GetBinaryData(CharDataVector &data) override;

    private:
        int version_;
        int signature_type_;
        HashAlgorithms hash_algo_;
        PublicKeyAlgorithms pub_key_algo_;
        KeyIDData key_id_;
        int nested_;
    };

    typedef std::shared_ptr<OnePassSignaturePacket> OnePassSignaturePacketPtr;
}

#endif /* cryptopg_OnePassSignaturePacket_ */

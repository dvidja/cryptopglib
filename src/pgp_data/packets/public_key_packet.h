//
//  PublicKeyPacket.h
//  cryptopg
//
//  Created by Anton Sarychev on 26.5.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_PublicKeyPacket_
#define cryptopg_PublicKeyPacket_


#include "../pgp_packet.h"
#include "../../crypto/public_key_algorithms.h"

namespace cryptopglib::pgp_data::packets {
    class PublicKeyPacket : public PGPPacket {
    public:
        explicit PublicKeyPacket(int key_version, bool is_subkey = false);

        PublicKeyPacket(PublicKeyPacket &public_key_packet);

        ~PublicKeyPacket() override;

        int GetKeyVersion();

        void SetTimestamp(unsigned int timestamp);

        unsigned int GetTimestamp();

        void SetKeyExpiredTime(unsigned int expired_time);

        unsigned int GetKeyExpiredTime();

        void SetPublicKeyAlgorithm(PublicKeyAlgorithms algo);

        PublicKeyAlgorithms GetPublicKeyAlgorithm();

        void AddMPI(CharDataVector mpi_data_);

        CharDataVector GetMPI(size_t index);

        void SetKeyID(KeyIDData &key_id);

        KeyIDData GetKeyID();

        void SetFingerprint(std::string fingerprint);

        std::string GetFingerprint();

        void SetKeySize(int size);

        int GetKeySize();

        bool GetRawData(CharDataVector &data) override;

        bool GetBinaryData(CharDataVector &data) override;

    private:
        int key_version_;
        unsigned int timestamp_;
        unsigned int expired_time_;
        PublicKeyAlgorithms algorithm_;
        std::vector<CharDataVector> mpis_;
        KeyIDData key_id_;
        std::string fingerprint_;
        int key_size_;
    };

    typedef std::shared_ptr<PublicKeyPacket> PublicKeyPacketPtr;
}
#endif /* cryptopg_PublicKeyPacket_ */

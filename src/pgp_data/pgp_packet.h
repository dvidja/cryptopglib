//
//  PGPPacket.h
//  cryptopg
//
//  Created by Anton Sarychev on 18.4.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_PGPPacket_
#define cryptopg_PGPPacket_

#include "pgp_packet_types.h"
#include "../utils/data_buffer.h"


namespace cryptopglib::pgp_data {
    double log2(double n);
    void GetKeyIDData(const KeyIDData& key_id, CharDataVector& key_id_data);

    class PGPPacket {
    public:
        explicit PGPPacket(PacketType packet_type);

        virtual ~PGPPacket() = default;

        PacketType GetPacketType();

        virtual bool GetRawData(CharDataVector &data) = 0;

        virtual bool GetBinaryData(CharDataVector &data) = 0;

    private:
        const PacketType packet_type_;
    };

    typedef std::shared_ptr<PGPPacket> PGPPacketPtr;
    typedef std::vector<PGPPacketPtr> PGPPacketsArray;
}
#endif /* cryptopg_PGPPacket_ */

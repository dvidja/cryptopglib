//
//  SymmetricallyEncryptedDataPacket.h
//  cryptopg
//
//  Created by Anton Sarychev on 6.8.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_SymmetricallyEncryptedDataPacket_
#define cryptopg_SymmetricallyEncryptedDataPacket_

#include "../pgp_packet.h"
namespace cryptopglib::pgp_data::packets {
    class SymmetricallyEncryptedDataPacket : public PGPPacket {
    public:
        explicit SymmetricallyEncryptedDataPacket(PacketType packet_type);

        void SetEncryptedData(CharDataVector &encrypted_data);

        const CharDataVector &GetEncryptedData();

        void SetMDCData(CharDataVector &encrypted_data);

        const CharDataVector &GetMDCData();

        bool GetRawData(CharDataVector &data) override;

        bool GetBinaryData(CharDataVector &data) override;

    private:
        CharDataVector encrypted_data_;
        CharDataVector mdc_data_;
    };

    typedef std::shared_ptr<SymmetricallyEncryptedDataPacket> SymmetricallyEncryptedDataPacketPtr;
}

#endif /* cryptopg_SymmetricallyEncryptedDataPacket_ */

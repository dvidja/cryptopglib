//
//  LiteralDataPacket.h
//  cryptopg
//
//  Created by Anton Sarychev on 11.8.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_LiteralDataPacket_
#define cryptopg_LiteralDataPacket_

#include "../pgp_packet.h"

namespace cryptopglib::pgp_data::packets {
    class LiteralDataPacket : public PGPPacket {
    public:
        LiteralDataPacket();

        void SetData(const CharDataVector &data);

        void SetFileName(const CharDataVector &file_name);

        CharDataVector &GetData();

        CharDataVector &GetFileName();

        bool GetRawData(CharDataVector &data) override;

        bool GetBinaryData(CharDataVector &data) override;

    private:

        CharDataVector data_;
        CharDataVector file_name_;
    };


    typedef std::shared_ptr<LiteralDataPacket> LiteralDataPacketPtr;
}
#endif /* cryptopg_LiteralDataPacket_ */

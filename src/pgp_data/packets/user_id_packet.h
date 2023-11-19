//
//  UserIDPacket.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.7.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_UserIDPacket_
#define cryptopg_UserIDPacket_


#include "../pgp_packet.h"

namespace cryptopglib::pgp_data::packets {
    class UserIDPacket : public PGPPacket {
    public:
        UserIDPacket();

        void SetUserID(const CharDataVector &user_id);

        std::string GetUserID();

        bool GetRawData(CharDataVector &data) override;

        bool GetBinaryData(CharDataVector &data) override;

    private:
        std::string user_id_;
    };


    typedef std::shared_ptr<UserIDPacket> UserIDPacketPtr;
}

#endif /* cryptopg_UserIDPacket_ */

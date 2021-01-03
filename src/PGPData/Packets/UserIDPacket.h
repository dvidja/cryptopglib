//
//  UserIDPacket.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.7.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__UserIDPacket__
#define __cryptopg__UserIDPacket__


#include "../PGPPacket.h"


class UserIDPacket : public PGPPacket
{
public:
    UserIDPacket();
    
    void SetUserID(const CharDataVector& user_id);
    std::string GetUserID();
    
    virtual bool GetRawData(CharDataVector& data);
    virtual bool GetBinaryData(CharDataVector& data);

private:
    std::string user_id_;
};


typedef std::shared_ptr<UserIDPacket> UserIDPacketPtr;


#endif /* defined(__cryptopg__UserIDPacket__) */

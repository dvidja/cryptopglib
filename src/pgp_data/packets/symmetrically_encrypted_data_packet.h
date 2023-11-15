//
//  SymmetricallyEncryptedDataPacket.h
//  cryptopg
//
//  Created by Anton Sarychev on 6.8.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__SymmetricallyEncryptedDataPacket__
#define __cryptopg__SymmetricallyEncryptedDataPacket__

#include "../pgp_packet.h"

class SymmetricallyEncryptedDataPacket : public PGPPacket
{
public:
    SymmetricallyEncryptedDataPacket(PacketType packet_type);
    
    void SetEncryptedData(CharDataVector& encrypted_data);
    const CharDataVector& GetEncryptedData();
    
    void SetMDCData(CharDataVector& encrypted_data);
    const CharDataVector& GetMDCData();
    
    virtual bool GetRawData(CharDataVector& data);
    virtual bool GetBinaryData(CharDataVector& data);

private:
    CharDataVector encrypted_data_;
    CharDataVector mdc_data_;
};

typedef std::shared_ptr<SymmetricallyEncryptedDataPacket> SymmetricallyEncryptedDataPacketPtr;

#endif /* defined(__cryptopg__SymmetricallyEncryptedDataPacket__) */

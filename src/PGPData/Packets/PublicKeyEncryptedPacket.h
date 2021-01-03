//
//  PublicKeyEncryptedPacket.h
//  cryptopg
//
//  Created by Anton Sarychev on 23.6.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__PublicKeyEncryptedPacket__
#define __cryptopg__PublicKeyEncryptedPacket__


#include "../PGPPacket.h"
#include "../../Crypto/PublicKeyAlgorithms.h"


class PublicKeyEncryptedPacket : public PGPPacket
{
public:
    PublicKeyEncryptedPacket();
    
    int GetVersion();
    KeyIDData GetKeyID();
    PublicKeyAlgorithms GetPublicKeyAlgorithm();
    CharDataVector GetMPI(size_t index);
    
    void SetublicKeyAlgorithm(PublicKeyAlgorithms algo);
    void SetKeyID(KeyIDData& key_id);
    void AddMPI(CharDataVector mpi_data_);
    
    virtual bool GetRawData(CharDataVector& data);
    virtual bool GetBinaryData(CharDataVector& data);
    
private:
    PublicKeyAlgorithms public_key_algorithm_;
    KeyIDData key_id_;
    std::vector<CharDataVector> mpis_;
};

typedef std::shared_ptr<PublicKeyEncryptedPacket> PublicKeyEncryptedPacketPtr;



#endif /* defined(__cryptopg__PublicKeyEncryptedPacket__) */

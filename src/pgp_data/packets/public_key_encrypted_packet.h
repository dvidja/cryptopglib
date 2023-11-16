//
//  PublicKeyEncryptedPacket.h
//  cryptopg
//
//  Created by Anton Sarychev on 23.6.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_PublicKeyEncryptedPacket_
#define cryptopg_PublicKeyEncryptedPacket_


#include "../pgp_packet.h"
#include "../../crypto/public_key_algorithms.h"


class PublicKeyEncryptedPacket : public PGPPacket
{
public:
    PublicKeyEncryptedPacket();
    
    int GetVersion();
    KeyIDData GetKeyID();
    PublicKeyAlgorithms GetPublicKeyAlgorithm();
    CharDataVector GetMPI(size_t index);
    
    void SetPublicKeyAlgorithm(PublicKeyAlgorithms algo);
    void SetKeyID(KeyIDData& key_id);
    void AddMPI(CharDataVector mpi_data_);
    
    bool GetRawData(CharDataVector& data) override;
    bool GetBinaryData(CharDataVector& data) override;
    
private:
    PublicKeyAlgorithms public_key_algorithm_;
    KeyIDData key_id_;
    std::vector<CharDataVector> mpis_;
};

typedef std::shared_ptr<PublicKeyEncryptedPacket> PublicKeyEncryptedPacketPtr;



#endif /* cryptopg_PublicKeyEncryptedPacket_ */

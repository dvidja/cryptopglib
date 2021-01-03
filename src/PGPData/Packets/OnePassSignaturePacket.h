//
//  OnePassSignaturePacket.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__OnePassSignaturePacket__
#define __cryptopg__OnePassSignaturePacket__

#include "../PGPPacket.h"
#include "../../Crypto/HashAlgorithms.h"
#include "../../Crypto/PublicKeyAlgorithms.h"
#include "SignaturePacket.h"

class OnePassSignaturePacket : public PGPPacket
{
public:
    OnePassSignaturePacket();
    OnePassSignaturePacket(SignaturePacketPtr signature_packet_ptr);
    
    void SetVersion(const int version = 3);
    void SetSignatureType(const int signature_type);
    void SetHashAlorithm(const HashAlgorithms hash_algo);
    void SetPublicKeyAlgorithm(const PublicKeyAlgorithms pub_key_algo);
    void SetKeyID(const KeyIDData& key_id);
    void SetNested(const int nested);
 
    int GetVersion();
    int GetSignatureType();
    HashAlgorithms GetHashAlorithm();
    PublicKeyAlgorithms GetPublicKeyAlgorithm();
    KeyIDData& GetKeyID();
    int GetNested();

    virtual bool GetRawData(CharDataVector& data);
    virtual bool GetBinaryData(CharDataVector& data);
    
private:
    int version_;
    int signature_type_;
    HashAlgorithms hash_algo_;
    PublicKeyAlgorithms pub_key_algo_;
    KeyIDData key_id_;
    int nested_;
};

typedef std::shared_ptr<OnePassSignaturePacket> OnePassSignaturePacketPtr;


#endif /* defined(__cryptopg__OnePassSignaturePacket__) */

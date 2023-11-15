//
//  SecretKeyPacket.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.7.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__SecretKeyPacket__
#define __cryptopg__SecretKeyPacket__


#include "../pgp_packet.h"
#include "public_key_packet.h"
#include "../../Crypto/hash_algorithms.h"
#include "../../Crypto/symmetric_key_algorithms.h"

class SecretKeyPacket : public PGPPacket
{
public:
    SecretKeyPacket(PublicKeyPacketPtr public_key_packet);
    SecretKeyPacket(SecretKeyPacket& secret_key_packet);
    
    PublicKeyPacketPtr GetPublicKeyPatr();
    
    KeyIDData GetKeyID();
    
    void AddMPI(CharDataVector mpi_data_);
    CharDataVector GetMPI(size_t index);
    
    void SetSymmetricKeyAlgorithm(SymmetricKeyAlgorithms sym_key_algo);
    SymmetricKeyAlgorithms GetSymmetricKeyAlgorithm();
    
    void SetStringToKeyHashAlgorithm(HashAlgorithms hash_algo);
    HashAlgorithms GetStringToKeyHashAlgorithm();
    
    void SetSaltValue(CharDataVector& salt_value);
    const CharDataVector& GetSaltValue();
    
    void SetInitialVector(CharDataVector& initial_vector);
    const CharDataVector& GetInitialVector();
    
    void SetStringToKeySpecefier(int string_to_key_specifier_type);
    int GetStringToKeySpecefier();
    
    void SetStringToKeyUsage(int string_to_key_usage);
    int GetStringToKeyUsage();
    
    void SetCount(int count);
    int GetCount();
    
    void ClearMPIData();
    
    virtual bool GetRawData(CharDataVector& data);
    virtual bool GetBinaryData(CharDataVector& data);
    
private:
    PublicKeyPacketPtr public_key_packet_;
    std::vector<CharDataVector> mpis_;
    
    SymmetricKeyAlgorithms symmetric_key_algo_; // 0 if data is not encrypt
    HashAlgorithms string_to_key_hash_algo_; // 0
    CharDataVector salt_; // size = 0 if no salt
    CharDataVector initial_vector_;
    int string_to_key_specifier_type_;
    int string_to_key_usage_;
    int count_;
};

typedef std::shared_ptr<SecretKeyPacket> SecretKeyPacketPtr;

#endif /* defined(__cryptopg__SecretKeyPacket__) */

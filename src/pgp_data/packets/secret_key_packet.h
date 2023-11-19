//
//  SecretKeyPacket.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.7.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_SecretKeyPacket_
#define cryptopg_SecretKeyPacket_


#include "../pgp_packet.h"
#include "public_key_packet.h"
#include "../../crypto/hash_algorithms.h"
#include "../../crypto/symmetric_key_algorithm.h"
#include "cryptopglib/SymmetricKeyAlgorithms.h"

class SecretKeyPacket : public PGPPacket
{
public:
    explicit SecretKeyPacket(PublicKeyPacketPtr public_key_packet);
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
    
    void SetStringToKeySpecifier(int string_to_key_specifier_type);
    int GetStringToKeySpecifier();
    
    void SetStringToKeyUsage(int string_to_key_usage);
    int GetStringToKeyUsage();
    
    void SetCount(int count);
    int GetCount();
    
    void ClearMPIData();
    
    bool GetRawData(CharDataVector& data) override;
    bool GetBinaryData(CharDataVector& data) override;
    
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

#endif /* cryptopg_SecretKeyPacket_ */

//
//  SignaturePacket.h
//  cryptopg
//
//  Created by Anton Sarychev on 13.6.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__SignaturePacket__
#define __cryptopg__SignaturePacket__

#include <map>

#include "../pgp_packet.h"
#include "../../Crypto/hash_algorithms.h"
#include "../../Crypto/public_key_algorithms.h"
#include "../../Crypto/symmetric_key_algorithms.h"
#include "../../Crypto/compression_algorithms.h"

typedef enum
{
    SST_SIGNATURE_CREATION_TIME = 2,
    SST_SIGNATURE_EXPIRATION_TIME = 3,
    SST_EXPORTABLE_CERTIFICATION = 4,
    SST_TRUST_SIGNATURE = 5,
    SST_REGULAR_EXPRESSION = 6,
    SST_REVOCABLE = 7,
    
    SST_KEY_EXPIRATION_TIME = 9,
    SST_PLACEHOLDER = 10,
    SST_PREFERRED_SYMMETRIC_ALGO = 11,
    SST_REVOCATION_KEY = 12,
    
    SST_ISSUER = 16,
    
    SST_NOTATION_DATA = 20,
    SST_PREFERRED_HASH_ALGO = 21,
    SST_PREFERRED_COMPRESSION_ALGO = 22,
    SST_KEY_SERVER_PREFERENCES = 23,
    SST_PREFERRED_KEY_SERVER = 24,
    SST_PRIMARY_USER_ID = 25,
    SST_POLICY_URI = 26,
    SST_KEY_FLAGS = 27,
    SST_SIGNER_USER_ID = 28,
    SST_REASON_FOR_REVOCATION = 29,
    SST_FEATURES = 30,
    SST_SIGNATURE_TRGET = 31,
    SST_EMBEDDED_SIGNATURE = 32,
    
} SignatureSubpacketType;


class SignaturePacket : public PGPPacket
{
private:
    struct Subpacket
    {
        SignatureSubpacketType subpacket_type_;
        CharDataVector data_;
        
        Subpacket(const SignatureSubpacketType subpacket_type, const CharDataVector& data)
        : subpacket_type_(subpacket_type)
        , data_(data)
        {
        }
    };

public:
    SignaturePacket(int version);
    
    int GetPacketVersion();
    int GetSignatureType();
    unsigned int GetCreationTime();
    const KeyIDData& GetKeyID();
	PublicKeyAlgorithms GetPublicKeyAlgorithm();
	HashAlgorithms GetHashAlgorithm();
	const std::vector<int>& GetDigestStart();
    unsigned int GetExpiredKeyTime();
    unsigned int GetExpiredSignatureTime();
    
	void SetSignatureType(int signature_type);
	void SetCreationTime(unsigned int creation_time);
	void SetKeyID(KeyIDData& key_id);
	void SetPublicKeyAlgorithm(PublicKeyAlgorithms public_key_algo);
	void SetHashAlgorithm(HashAlgorithms hash_algo);
	void SetDigestStart(std::vector<int>& digest_start);
    void SetExpiredKeyTime(unsigned int expired_key_time);
    void SetExpiredSignatureTime(unsigned int expired_key_time);
    
    void AddMPI(CharDataVector mpi_data_);
    const CharDataVector GetMPI(size_t index);
    
    void AddSubpacketData(const SignatureSubpacketType subpacket_type, const CharDataVector& data, bool hashed);
    void GetDataForHash(CharDataVector& data);
    
    void SetPreferedHahAlgos(std::vector<HashAlgorithms> algos);
    void SetPreferedChiperAlgos(std::vector<SymmetricKeyAlgorithms> algos);
    void SetPreferedCompressionAlgos(std::vector<CompressionAlgorithms> algos);
    
    std::vector<HashAlgorithms> GetPreferedHahAlgos();
    std::vector<SymmetricKeyAlgorithms> GetPreferedChiperAlgos();
    std::vector<CompressionAlgorithms> GetPreferedCompressionAlgos();
    
    virtual bool GetRawData(CharDataVector& data);
    virtual bool GetBinaryData(CharDataVector& data);
    
private:
    void GetSubpacketBinaryData(const Subpacket& subpacket, CharDataVector& subpacket_data);
    
    bool GetRawDataForV3Packet(CharDataVector& data);
    bool GetRawDataForV4Packet(CharDataVector& data);
    
private:
    int packet_version_;
    int signature_type_;
    unsigned int creation_time_;
    KeyIDData key_id_;
    PublicKeyAlgorithms public_key_algo_;
    HashAlgorithms hash_algo_;
    std::vector<int> digest_start_;
    
    std::vector<Subpacket> hashed_subpackets_;
    std::vector<Subpacket> unhashed_subpackets_;

    std::vector<CharDataVector> mpis_;
    
    unsigned int expired_key_time_;
    unsigned int expired_signature_time_;
    
    std::vector<HashAlgorithms> prefered_hash_algorithms_;
    std::vector<SymmetricKeyAlgorithms> prefered_chiper_algorithms_;
    std::vector<CompressionAlgorithms> prefered_compression_algorithms_;
    
};

typedef std::shared_ptr<SignaturePacket> SignaturePacketPtr;

#endif /* defined(__cryptopg__SignaturePacket__) */

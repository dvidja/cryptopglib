//
//  PublicKeyAlgorithmsImpl.h
//  cryptopg
//
//  Created by Anton Sarychev on 5.11.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_PublicKeyAlgorithmsImpl_
#define cryptopg_PublicKeyAlgorithmsImpl_


#include "public_key_algorithms.h"

#include "../pgp_data/packets/secret_key_packet.h"
#include "../pgp_data/packets/public_key_encrypted_packet.h"


namespace  crypto
{
    class PublicKeyAlgorithm
    {
    public:
        virtual ~PublicKeyAlgorithm() = default;

        virtual int EncryptWithPrivateKey(SecretKeyPacketPtr secret_key, const CharDataVector& source_data, CharDataVector& result_data) = 0;
        virtual int EncryptWithPublicKey(PublicKeyPacketPtr public_key, const CharDataVector& source_data, CharDataVector& result_data) = 0;
        
        virtual int DecryptWithPrivateKey(SecretKeyPacketPtr secret_key, const CharDataVector& source_data, CharDataVector& result_data) = 0;
        virtual int DecryptWithPublicKey(PublicKeyPacketPtr public_key, const CharDataVector& source_data, CharDataVector& result_data) = 0;
    };
    
    typedef std::unique_ptr<PublicKeyAlgorithm> PublicKeyAlgorithmPtr;
    
    
    class RSAAlgorithm : public PublicKeyAlgorithm
    {
    public:
        int EncryptWithPrivateKey(SecretKeyPacketPtr secret_key,
                                  const CharDataVector& source_data,
                                  CharDataVector& result_data) override;
        int EncryptWithPublicKey(PublicKeyPacketPtr public_key,
                                         const CharDataVector& source_data,
                                         CharDataVector& result_data) override;
        
        int DecryptWithPrivateKey(SecretKeyPacketPtr secret_key,
                                  const CharDataVector& source_data,
                                  CharDataVector& result_data) override;
        int DecryptWithPublicKey(PublicKeyPacketPtr public_key,
                                 const CharDataVector& source_data,
                                 CharDataVector& result_data) override;
    };

    class DSSDHAlgorithm : public PublicKeyAlgorithm
    {
    public:
        int EncryptWithPrivateKey(SecretKeyPacketPtr secret_key,
                                  const CharDataVector& source_data,
                                  CharDataVector& result_data) override;
        int EncryptWithPublicKey(PublicKeyPacketPtr public_key,
                                 const CharDataVector& source_data,
                                 CharDataVector& result_data) override;
        
        int DecryptWithPrivateKey(SecretKeyPacketPtr secret_key,
                                  const CharDataVector& source_data,
                                  CharDataVector& result_data) override;
        int DecryptWithPublicKey(PublicKeyPacketPtr public_key,
                                 const CharDataVector& source_data,
                                 CharDataVector& result_data) override;
    };

    PublicKeyAlgorithmPtr GetPublicKeyAlgorithm(PublicKeyAlgorithms algo);
}

#endif /* cryptopg_PublicKeyAlgorithmsImpl_ */

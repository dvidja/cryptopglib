//
//  PublicKeyAlgorithmsImpl.h
//  cryptopg
//
//  Created by Anton Sarychev on 5.11.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__PublicKeyAlgorithmsImpl__
#define __cryptopg__PublicKeyAlgorithmsImpl__


#include "PublicKeyAlgorithms.h"

#include "../PGPData/Packets/SecretKeyPacket.h"
#include "../PGPData/Packets/PublicKeyEncryptedPacket.h"


namespace  crypto
{
    class PublicKeyAlgorithm
    {
    public:
        virtual int EncryptWithPrivateKey(SecretKeyPacketPtr secret_key, const CharDataVector& source_data, CharDataVector& result_data) = 0;
        virtual int EncryptWithPublicKey(PublicKeyPacketPtr public_key, const CharDataVector& source_data, CharDataVector& result_data) = 0;
        
        virtual int DecryptWithPrivateKey(SecretKeyPacketPtr secret_key, const CharDataVector& source_data, CharDataVector& result_data) = 0;
        virtual int DecryptWithPublicKey(PublicKeyPacketPtr public_key, const CharDataVector& source_data, CharDataVector& result_data) = 0;
    };
    
    typedef std::shared_ptr<PublicKeyAlgorithm> PublicKeyAlgorithmPtr;
    
    
    class RSAAlgorithm : public PublicKeyAlgorithm
    {
    public:
        virtual int EncryptWithPrivateKey(SecretKeyPacketPtr secret_key, const CharDataVector& source_data, CharDataVector& result_data);
        virtual int EncryptWithPublicKey(PublicKeyPacketPtr public_key, const CharDataVector& source_data, CharDataVector& result_data);
        
        virtual int DecryptWithPrivateKey(SecretKeyPacketPtr secret_key, const CharDataVector& source_data, CharDataVector& result_data);
        virtual int DecryptWithPublicKey(PublicKeyPacketPtr public_key, const CharDataVector& source_data, CharDataVector& result_data);
    };

    class DSSDHAlgorithm : public PublicKeyAlgorithm
    {
    public:
        virtual int EncryptWithPrivateKey(SecretKeyPacketPtr secret_key, const CharDataVector& source_data, CharDataVector& result_data);
        virtual int EncryptWithPublicKey(PublicKeyPacketPtr public_key, const CharDataVector& source_data, CharDataVector& result_data);
        
        virtual int DecryptWithPrivateKey(SecretKeyPacketPtr secret_key, const CharDataVector& source_data, CharDataVector& result_data);
        virtual int DecryptWithPublicKey(PublicKeyPacketPtr public_key, const CharDataVector& source_data, CharDataVector& result_data);
    };

    
    PublicKeyAlgorithmPtr GetPublicKeyAlgorithm(PublicKeyAlgorithms algo);
}

#endif /* defined(__cryptopg__SymmetricKeyAlgorithmsImpl__) */

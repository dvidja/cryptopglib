//
//  IOpenPGPInfoGetter.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.7.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_IOpenPGPInfoGetter_h
#define cryptopg_IOpenPGPInfoGetter_h

#include "PGPData/PGPDataTypes.h"

class IOpenPGPInfoGetter
{
public:
    virtual std::string GetPublicKeyByID(const KeyIDData& key_id) = 0;
    virtual std::string GetSecretKeyByID(const KeyIDData& key_id) = 0;
    
    virtual int GetPublicKeyAlgorithmForSign() = 0;
    virtual int GetPublicKeyAlgorithmForEncrypt() = 0;
    virtual int GetHashAlgorithmForSign() = 0;
    virtual int GetCompressAlgorithm() = 0;
    virtual int GetSymmetricKeyAlgorithm() = 0;
};

typedef std::shared_ptr<IOpenPGPInfoGetter> IOpenPGPInfoGetterPtr;

#endif

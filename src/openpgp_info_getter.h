//
//  IOpenPGPInfoGetter.h
//  cryptopg
//
//  Created by Anton Sarychev on 2.7.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#pragma once

#include "pgp_data/pgp_data_types.h"

namespace cryptopglib {
    class OpenPGPInfoGetter {
    public:
        virtual ~OpenPGPInfoGetter() = default;

        virtual std::string GetPublicKeyByID(const KeyIDData &key_id) = 0;

        virtual std::string GetSecretKeyByID(const KeyIDData &key_id) = 0;

        virtual int GetPublicKeyAlgorithmForSign() = 0;

        virtual int GetPublicKeyAlgorithmForEncrypt() = 0;

        virtual int GetHashAlgorithmForSign() = 0;

        virtual int GetCompressAlgorithm() = 0;

        virtual int GetSymmetricKeyAlgorithm() = 0;
    };

    typedef std::shared_ptr<OpenPGPInfoGetter> OpenPGPInfoGetterPtr;
}
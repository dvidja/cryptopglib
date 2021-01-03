//
//  PGPEncrypt.h
//  cryptopg
//
//  Created by Anton Sarychev on 3.11.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__PGPEncrypt__
#define __cryptopg__PGPEncrypt__

#include "../PGPMessageImpl.h"
#include "../IOpenPGPInfoGetter.h"

namespace crypto
{
    class PGPEncrypt
    {
    public:
        PGPEncrypt();
        
        PGPMessagePtr EncryptMessage(const std::string& plain_text, std::vector<PGPMessagePtr>& addressers_pub_keys_ptr, PGPMessagePtr own_key_ptr, IOpenPGPInfoGetterPtr pgp_info_getter_);
        PGPMessagePtr EncryptRawData(const CharDataVector& data, std::vector<PGPMessagePtr>& addressers_pub_keys_ptr, PGPMessagePtr own_key_ptr, IOpenPGPInfoGetterPtr pgp_info_getter_);
        
    };
}


#endif /* defined(__cryptopg__PGPEncrypt__) */

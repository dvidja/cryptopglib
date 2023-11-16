//
//  PGPEncrypt.h
//  cryptopg
//
//  Created by Anton Sarychev on 3.11.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_PGPEncrypt_
#define cryptopg_PGPEncrypt_

#include "../pgp_message_impl.h"
#include "../openpgp_info_getter.h"

namespace crypto
{
    class PGPEncrypt
    {
    public:
        PGPEncrypt();
        
        PGPMessagePtr EncryptMessage(const std::string& plain_text,
                                     std::vector<PGPMessagePtr>& addressers_pub_keys_ptr,
                                     PGPMessagePtr own_key_ptr,
                                     OpenPGPInfoGetterPtr pgp_info_getter_);

        PGPMessagePtr EncryptRawData(const CharDataVector& data,
                                     std::vector<PGPMessagePtr>& addressers_pub_keys_ptr,
                                     PGPMessagePtr own_key_ptr,
                                     OpenPGPInfoGetterPtr pgp_info_getter_);
        
    };
}


#endif /* cryptopg_PGPEncrypt_ */

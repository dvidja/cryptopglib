//
//  PGPCreator.h
//  cryptopg
//
//  Created by Anton Sarychev on 28.7.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_PGPCreator_
#define cryptopg_PGPCreator_

#include <vector>

#include "../open_pgp_impl.h"




class PGPCreator
{
public:
    static bool GetBinaryRepresentationOfMessage(PGPMessagePtr message_impl,
                                                 CharDataVector& data,
                                                 bool armored = false);
};

#endif /* cryptopg_PGPCreator_ */

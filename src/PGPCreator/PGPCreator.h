//
//  PGPCreator.h
//  cryptopg
//
//  Created by Anton Sarychev on 28.7.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__PGPCreator__
#define __cryptopg__PGPCreator__

#include <vector>

#include "../OpenPGPImpl.h"




class PGPCreator
{
public:
    static bool GetBinaryRepresentationOfMessage(PGPMessagePtr message_impl, CharDataVector& data, bool armored = false);
};

#endif /* defined(__cryptopg__PGPCreator__) */

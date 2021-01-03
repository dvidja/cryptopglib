//
//  PGPMessageType.h
//  cryptopg
//
//  Created by Anton Sarychev on 22.4.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef CRYPTOPGLIB_PGPMESSAGETYPE_H
#define CRYPTOPGLIB_PGPMESSAGETYPE_H

typedef enum
{
    MT_PUBLIC_KEY = 0,
    MT_PRIVATE_KEY,
    MT_CRYPTO_MESSAGE,
    MT_SIGNED_MESSAGE,
    MT_SIMPLE_MESSAGE,

    MT_INCORRECT_MESSAGE = 256,
} PGPMessageType;

#endif //CRYPTOPGLIB_PGPMESSAGETYPE_H

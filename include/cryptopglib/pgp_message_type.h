//
//  PGPMessageType.h
//  cryptopg
//
//  Created by Anton Sarychev on 22.4.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#pragma once

    enum class PGPMessageType {
        kPublicKey = 0,
        kPrivateKey,
        kEncryptedMessage,
        kSignedMessage,
        kPlainTextMessage,

        kIncorrectMessage = 256,
    };



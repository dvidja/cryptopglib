//
// Created by Anton Sarychev on 2.12.23.
//
#include "cryptopglib/pgp_message.h"

namespace cryptopglib {
    PGPMessageType PGPMessage::GetMessageType() {
        return PGPMessageType::kIncorrectMessage;
    }
}

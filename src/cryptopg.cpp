#include "../include/cryptopglib/cryptopg.h"
#include "pgp_parser/pgp_parser.h"


namespace cryptopglib
{
    void GetPPGKeyInfo(std::string&& pgp_key_data) {

        auto message = PGPParser().ParseMessage(pgp_key_data);
        if (message->GetMessageType() != PGPMessageType::MT_PRIVATE_KEY ||
            message->GetMessageType() != PGPMessageType::MT_PUBLIC_KEY)
        {
            return;
        }


    }
}

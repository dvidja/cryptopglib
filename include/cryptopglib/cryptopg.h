#pragma once

#include <string>

#include "pgp_key.h"
#include "pgp_message.h"


namespace cryptopglib {

    PGPMessage ReadPGPMessage(const std::string& message);
    //PGPMessage ReadPGPMessage(const std::vector<unsigned char>& data);

    //
    PGPKey GetPPGKeyInfo(const std::string& pgp_key_data);

    //


    //CheckSignature - from simple string of from pgpmessage
    //SignMessage

    //DecryptMessage (here may be signed and encrypted message, here will return a PGPMessage
    // struct with message and key ids to check signature)

    //EncryptMessage
    //SignAndEncrypt

    //GeneratePGPKey(PKalgorithm, passpharase, ...)
    //

}
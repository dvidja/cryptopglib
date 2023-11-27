#include "../include/cryptopglib/cryptopg.h"
#include "pgp_parser/pgp_parser.h"
#include "open_pgp_impl.h"


namespace cryptopglib
{
    PGPMessage ReadPGPMessage(const std::string& message) {
        auto message_ptr = pgp_parser::PGPParser().ParseMessage(message);

        return PGPMessage {};
    }

    PGPKey GetPPGKeyInfo(const std::string& pgp_key_data) {
        OpenPGPImpl open_pgp(nullptr);

        auto key_info_impl = open_pgp.GetKeyInfo(pgp_key_data);

        return PGPKey {key_info_impl.key_fingerprint_, key_info_impl.users_id_, false, false};
    }
}

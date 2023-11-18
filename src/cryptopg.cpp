#include "../include/cryptopglib/cryptopg.h"
#include "pgp_parser/pgp_parser.h"
#include "open_pgp_impl.h"


namespace cryptopglib
{
    PGPKeyInfo GetPPGKeyInfo(std::string&& pgp_key_data) {
        OpenPGPImpl open_pgp(nullptr);

        auto key_info_impl = open_pgp.GetKeyInfo(pgp_key_data);

        return PGPKeyInfo {key_info_impl.key_fingerprint_, key_info_impl.users_id_};
    }
}

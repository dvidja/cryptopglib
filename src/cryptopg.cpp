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

    std::ostream& operator<<(std::ostream& stream, const PGPKeyInfo& pgp_key_info) {
        stream << "Fingerprint: " << pgp_key_info.key_fingerprint << std::endl;
        stream << "Users count: " << pgp_key_info.users_id.size() << std::endl;
        for (const auto& user: pgp_key_info.users_id)
        {
            stream << "\t" << user << std::endl;
        }

        return stream;
    }
}

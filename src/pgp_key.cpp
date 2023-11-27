//
// Created by Anton Sarychev on 20.11.23.
//

#include "cryptopglib/pgp_key.h"

namespace cryptopglib {
    std::ostream& operator<<(std::ostream& stream, const PGPKey& pgp_key_info) {
        stream << "Fingerprint: " << pgp_key_info.key_fingerprint << std::endl;
        stream << "Users count: " << pgp_key_info.users_id.size() << std::endl;
        for (const auto& user: pgp_key_info.users_id)
        {
            stream << "\t" << user << std::endl;
        }

        return stream;
    }
}
//
//  PGPPacketTypes.h
//  cryptopg
//
//  Created by Anton Sarychev on 18.4.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_PGPPacketTypes_h
#define cryptopg_PGPPacketTypes_h

namespace cryptopglib {
     enum class PacketType {
        kNone = 0,
        kPublicKeyEncryptedPacket = 1,  /* Public key encrypted packet. */
        kSignaturePacket = 2,  /* Secret key encrypted packet. */
        kSymmetricKeyEncryptedSessionKeyPacket = 3,  /* Session key packet. */
        kOnePassSignaturePacket = 4,  /* One pass sig packet. */
        kSecretKeyPacket = 5,  /* Secret key. */
        kPublicKeyPacket = 6,  /* Public key. */
        kSecretSubkeyPacket = 7,  /* Secret subkey. */
        kCompressedDataPacket = 8,  /* Compressed data packet. */
        kSymmetricallyEncryptedDataPacket = 9,  /* Conventional encrypted data. */
        kMarkerPacket = 10, /* Marker packet. */
        kLiteralDataPacket = 11, /* Literal data packet. */
        kTrustPacket = 12, /* Keyring trust packet. */
        kUserIDPacket = 13, /* User id packet. */
        kPublicSubkeyPacket = 14, /* Public subkey. */
        kUserAttributePacket = 17, /* PGP's attribute packet. */
        kSymmetricEncryptedAndIntegrityProtectedDataPacket = 18, /* Integrity protected encrypted data. */
        kModificationDetectionCodePacket = 19, /* Manipulation detection code packet. */

        //// from GnuPG
        kComment [[maybe_unused]] = 61, /* new comment packet (GnuPG specific). */
        kGPGControl [[maybe_unused]] = 63  /* internal control packet (GnuPG specific). */
    };
}

#endif

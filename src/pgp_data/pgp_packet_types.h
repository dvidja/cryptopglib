//
//  PGPPacketTypes.h
//  cryptopg
//
//  Created by Anton Sarychev on 18.4.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_PGPPacketTypes_h
#define cryptopg_PGPPacketTypes_h

typedef enum
{
    PT_NONE                                                     = 0,
    PT_PUBLIC_KEY_ENCRYPTED_PACKET                              = 1,  /* Public key encrypted packet. */
    PT_SIGNATURE_PACKET                                         = 2,  /* Secret key encrypted packet. */
    PT_SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY_PACKET               = 3,  /* Session key packet. */
    PT_ONE_PASS_SIGNATURE_PACKET                                = 4,  /* One pass sig packet. */
    PT_SECRET_KEY_PACKET                                        = 5,  /* Secret key. */
    PT_PUBLIC_KEY_PACKET                                        = 6,  /* Public key. */
    PT_SECRET_SUBKEY_PACKET                                     = 7,  /* Secret subkey. */
    PT_COMPRESSED_DATA_PACKET                                   = 8,  /* Compressed data packet. */
    PT_SYMMETRICALLY_ENCRYPTED_DATA_PACKET                      = 9,  /* Conventional encrypted data. */
    PT_MARKER_PACKET                                            = 10, /* Marker packet. */
    PT_LITERAL_DATA_PACKET                                      = 11, /* Literal data packet. */
    PT_TRUST_PACKET                                             = 12, /* Keyring trust packet. */
    PT_USER_ID_PACKET                                           = 13, /* User id packet. */
    PT_PUBLIC_SUBKEY_PACKET                                     = 14, /* Public subkey. */
    PT_USER_ATTRIBUTE_PACKET                                    = 17, /* PGP's attribute packet. */
    PT_SYMMETRIC_ENCRYTPED_AND_INTEGRITY_PROTECTED_DATA_PACKET  = 18, /* Integrity protected encrypted data. */
    PT_MODIFICATION_DETECTION_CODE_PACKET                       = 19, /* Manipulation detection code packet. */
    
    //// from GnuPG
    PT_COMMENT                                                  = 61, /* new comment packet (GnuPG specific). */
    PT_GPG_CONTROL                                              = 63  /* internal control packet (GnuPG specific). */
} PacketType;


#endif

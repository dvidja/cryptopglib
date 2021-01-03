project(cryptopglib)

set (CRYPTOPGLIBSOURCES
        ${CRYPTOPGLIBSOURCES}
        cryptopg.cpp
        OpenPGPImpl.cpp
        PGPErrors.cpp
        PGPMessageImpl.cpp
        Crypto/CompressionAlgorithms.cpp
        Crypto/HashAlgorithms.cpp
        Crypto/KeyGenerator.cpp
        Crypto/PGPDecrypt.cpp
        Crypto/PGPEncrypt.cpp
        Crypto/PGPKeyData.cpp
        Crypto/PGPSignature.cpp
        Crypto/PublicKeyAlgorithmsImpl.cpp
        Crypto/SymmetricKeyAlgorithms.cpp
        PGPCreator/PGPCreator.cpp
        PGPData/PGPPacket.cpp
        PGPData/Packets/CompressedDataPacket.cpp
        PGPData/Packets/LiteralDataPacket.cpp
        PGPData/Packets/MarkerPacket.cpp
        PGPData/Packets/ModificationDetectionCodePacket.cpp
        PGPData/Packets/OnePassSignaturePacket.cpp
        PGPData/Packets/PublicKeyEncryptedPacket.cpp
        PGPData/Packets/PublicKeyPacket.cpp
        PGPData/Packets/SecretKeyPacket.cpp
        PGPData/Packets/SignaturePacket.cpp
        PGPData/Packets/SymmetricallyEncryptedDataPacket.cpp
        PGPData/Packets/SymmetricKeyEncryptedSessionKeyPacket.cpp
        PGPData/Packets/TrustPacket.cpp
        PGPData/Packets/UserAttributePacket.cpp
        PGPData/Packets/UserIDPacket.cpp
        PGPParser/PGPMessageParser.cpp
        PGPParser/PGPPacketsParser.cpp
        PGPParser/PGPParser.cpp
        PGPParser/PacketParsers/CompressedDataPacketParser.cpp
        PGPParser/PacketParsers/LiteralDataPacketParser.cpp
        PGPParser/PacketParsers/MarkerPacketParser.cpp
        PGPParser/PacketParsers/ModificationDetectionCodePacketParser.cpp
        PGPParser/PacketParsers/OnePassSignaturePacketParser.cpp
        PGPParser/PacketParsers/PacketParser.cpp
        PGPParser/PacketParsers/PublicKeyEnctyptedPacketParser.cpp
        PGPParser/PacketParsers/PublicKeyPacketParser.cpp
        PGPParser/PacketParsers/SecretKeyPacketParser.cpp
        PGPParser/PacketParsers/SignaturePacketParser.cpp
        PGPParser/PacketParsers/SymmetricallyEncryptedDataPacketParser.cpp
        PGPParser/PacketParsers/SymmetricKeyEncryptedSessionKeyPacketParser.cpp
        PGPParser/PacketParsers/TrustPacketParser.cpp
        PGPParser/PacketParsers/UserAttributePacketParser.cpp
        PGPParser/PacketParsers/UserIDPacketParser.cpp
        Utils/base64.cpp
        Utils/crc24.cpp
        Utils/DataBuffer.cpp
        )

add_library( cryptopglib STATIC ${CRYPTOPGLIBSOURCES})


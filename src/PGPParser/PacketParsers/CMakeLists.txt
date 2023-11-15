
target_sources(cryptopglib PUBLIC
        CompressedDataPacketParser.cpp
        LiteralDataPacketParser.cpp
        MarkerPacketParser.cpp
        ModificationDetectionCodePacketParser.cpp
        OnePassSignaturePacketParser.cpp
        PacketParser.cpp
        PublicKeyEnctyptedPacketParser.cpp
        PublicKeyPacketParser.cpp
        SecretKeyPacketParser.cpp
        SignaturePacketParser.cpp
        SymmetricallyEncryptedDataPacketParser.cpp
        SymmetricKeyEncryptedSessionKeyPacketParser.cpp
        TrustPacketParser.cpp
        UserAttributePacketParser.cpp
        UserIDPacketParser.cpp
)
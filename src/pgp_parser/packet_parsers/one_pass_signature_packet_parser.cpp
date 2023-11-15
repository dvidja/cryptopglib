//
//  OnePassSignaturePacketParser.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "one_pass_signature_packet_parser.h"



OnePassSignaturePacket* OnePassSignaturePacketParser::Parse(DataBuffer& data_buffer, bool partial, int c)
{
    int version_number = data_buffer.GetNextByte();
    if (version_number != 3)
    {
        return nullptr;
    }
    
    OnePassSignaturePacket* packet = new OnePassSignaturePacket;
    packet->SetVersion(version_number);
    
    int signature_type = data_buffer.GetNextByte();
    packet->SetSignatureType(signature_type);
    
    HashAlgorithms hash_algo = static_cast<HashAlgorithms>(data_buffer.GetNextByte());
    packet->SetHashAlorithm(hash_algo);
    
    PublicKeyAlgorithms pub_key_algo = static_cast<PublicKeyAlgorithms>(data_buffer.GetNextByte());
    packet->SetPublicKeyAlgorithm(pub_key_algo);
    
    KeyIDData key_id(2);
    key_id[0] = data_buffer.GetNextFourOctets();
    key_id[1] = data_buffer.GetNextFourOctets();
    packet->SetKeyID(key_id);
    
    int nested = data_buffer.GetNextByte();
    packet->SetNested(nested);
    
    return packet;
}
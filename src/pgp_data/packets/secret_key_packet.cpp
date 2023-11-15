//
//  SecretKeyPacket.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 2.7.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "secret_key_packet.h"


SecretKeyPacket::SecretKeyPacket(PublicKeyPacketPtr public_key_packet)
    : PGPPacket(public_key_packet->GetPacketType() == PT_PUBLIC_KEY_PACKET ? PT_SECRET_KEY_PACKET : PT_SECRET_SUBKEY_PACKET)
    , public_key_packet_(public_key_packet)
    , symmetric_key_algo_(SKA_PLAIN_TEXT)
    , string_to_key_hash_algo_(HA_NO_HASH)
{
}

SecretKeyPacket::SecretKeyPacket(SecretKeyPacket& secret_key_packet)
    : PGPPacket(secret_key_packet.GetPacketType())
{
    public_key_packet_.reset(new PublicKeyPacket(*secret_key_packet.GetPublicKeyPatr()));
    mpis_.assign(secret_key_packet.mpis_.begin(), secret_key_packet.mpis_.end());
    symmetric_key_algo_ = secret_key_packet.symmetric_key_algo_;
    string_to_key_hash_algo_ = secret_key_packet.string_to_key_hash_algo_;
    salt_.assign(secret_key_packet.salt_.begin(), secret_key_packet.salt_.end());
    initial_vector_.assign(secret_key_packet.initial_vector_.begin(), secret_key_packet.initial_vector_.end());
    string_to_key_specifier_type_ = secret_key_packet.string_to_key_specifier_type_;
    string_to_key_usage_ = secret_key_packet.string_to_key_usage_;
    count_ = secret_key_packet.count_;
}

PublicKeyPacketPtr SecretKeyPacket::GetPublicKeyPatr()
{
    return public_key_packet_;
}

KeyIDData SecretKeyPacket::GetKeyID()
{
    return public_key_packet_->GetKeyID();
}

void SecretKeyPacket::AddMPI(CharDataVector mpi_data)
{
    mpis_.push_back(mpi_data);
}

CharDataVector SecretKeyPacket::GetMPI(size_t index)
{
    if ((mpis_.size() != 0) && (index < mpis_.size()))
    {
        return mpis_[index];
    }
    
    return CharDataVector();
}

void SecretKeyPacket::SetSymmetricKeyAlgorithm(SymmetricKeyAlgorithms sym_key_algo)
{
    symmetric_key_algo_ = sym_key_algo;
}

SymmetricKeyAlgorithms SecretKeyPacket::GetSymmetricKeyAlgorithm()
{
    return symmetric_key_algo_;
}

void SecretKeyPacket::SetStringToKeyHashAlgorithm(HashAlgorithms hash_algo)
{
    string_to_key_hash_algo_ = hash_algo;
}

HashAlgorithms SecretKeyPacket::GetStringToKeyHashAlgorithm()
{
    return  string_to_key_hash_algo_;
}

void SecretKeyPacket::SetSaltValue(CharDataVector& salt_value)
{
    salt_.assign(salt_value.begin(), salt_value.end());
}

const CharDataVector& SecretKeyPacket::GetSaltValue()
{
    return salt_;
}

void SecretKeyPacket::SetInitialVector(CharDataVector& initial_vector)
{
    initial_vector_.assign(initial_vector.begin(), initial_vector.end());
}

const CharDataVector& SecretKeyPacket::GetInitialVector()
{
    return initial_vector_;
}

void SecretKeyPacket::SetStringToKeySpecefier(int string_to_key_specifier_type)
{
    string_to_key_specifier_type_ = string_to_key_specifier_type;
}

int SecretKeyPacket::GetStringToKeySpecefier()
{
    return string_to_key_specifier_type_;
}

void SecretKeyPacket::SetStringToKeyUsage(int string_to_key_usage)
{
    string_to_key_usage_ = string_to_key_usage;
}

int SecretKeyPacket::GetStringToKeyUsage()
{
    return string_to_key_usage_;
}

void SecretKeyPacket::SetCount(int count)
{
    count_ = count;
}

int SecretKeyPacket::GetCount()
{
    return ((16 + (count_ & 15)) << ((count_ >> 4) + 6));
}

void SecretKeyPacket::ClearMPIData()
{
    mpis_.clear();
}

bool SecretKeyPacket::GetRawData(CharDataVector& data)
{
    CharDataVector temp_data;
    
   if (!GetPublicKeyPatr()->GetRawData(temp_data))
   {
       return false;
   }
    
    temp_data.push_back(GetStringToKeyUsage());
    
    if(GetStringToKeyUsage() == 254 || GetStringToKeyUsage() == 255)
    {
        temp_data.push_back(GetSymmetricKeyAlgorithm());
        
        temp_data.push_back(GetStringToKeySpecefier());
        temp_data.push_back(GetStringToKeyHashAlgorithm());
        temp_data.insert(temp_data.end(), salt_.begin(), salt_.end());
        temp_data.push_back(count_);
    }
    
    if (GetStringToKeyUsage() != 0)
    {
        temp_data.insert(temp_data.end(), initial_vector_.begin(), initial_vector_.end());
    }
    
    for (auto iter = mpis_.begin(); iter != mpis_.end(); ++iter)
    {
        temp_data.insert(temp_data.end(), iter->begin(), iter->end());
    }
    
    data.insert(data.end(), temp_data.begin(), temp_data.end());
    
    return true;
}

bool SecretKeyPacket::GetBinaryData(CharDataVector& data)
{
    CharDataVector temp_data;
    
    if (!GetRawData(temp_data))
    {
        return false;
    }
    
    ///////////////////////////////
    unsigned char c = 0;
    c ^= 0x80;
    c ^= 0x40;
    c ^= GetPacketType();
    data.push_back(c);
    
    if (temp_data.size() < 192)
    {
        data.push_back(temp_data.size());
    }
    else if (temp_data.size() < 8384)
    {
        int length = static_cast<int>(temp_data.size()) - 192;
        data.push_back((length / 256) + 192);
        data.push_back(length % 256);
    }
    else
    {
        int length = static_cast<int>(temp_data.size());
        data.push_back(0xff);
        data.push_back((length >> 24) & 0xff);
        data.push_back((length >> 16) & 0xff);
        data.push_back((length >> 8) & 0xff);
        data.push_back(length & 0xff);
    }
    
    data.insert(data.end(), temp_data.begin(), temp_data.end());
    
    return true;
}


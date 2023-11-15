//
//  SignaturePacket.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 13.6.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "signature_packet.h"
#include <cmath>


SignaturePacket::SignaturePacket(int version)
    : PGPPacket(PT_SIGNATURE_PACKET)
    , packet_version_(version)
    , expired_key_time_(0)
{
    
}

int SignaturePacket::GetPacketVersion()
{
    return packet_version_;
}

int SignaturePacket::GetSignatureType()
{
    return signature_type_;
}

unsigned int SignaturePacket::GetCreationTime()
{
    return creation_time_;
}

const KeyIDData& SignaturePacket::GetKeyID()
{
    return key_id_;
}

PublicKeyAlgorithms SignaturePacket::GetPublicKeyAlgorithm()
{
    return public_key_algo_;
}

HashAlgorithms SignaturePacket::GetHashAlgorithm()
{
    return hash_algo_;
}

const std::vector<int>& SignaturePacket::GetDigestStart()
{
    return digest_start_;
}

unsigned int SignaturePacket::GetExpiredKeyTime()
{
    return expired_key_time_;
}

unsigned int SignaturePacket::GetExpiredSignatureTime()
{
    return expired_signature_time_;
}

void SignaturePacket::SetSignatureType(int signature_type)
{
	signature_type_ = signature_type;
}

void SignaturePacket::SetCreationTime(unsigned int creation_time)
{
	creation_time_ = creation_time;
    
    if (packet_version_ == 4)
    {
        CharDataVector data;
        data.push_back((creation_time >> 24) & 0xff);
        data.push_back((creation_time >> 16) & 0xff);
        data.push_back((creation_time >> 8) & 0xff);
        data.push_back(creation_time & 0xff);

        AddSubpacketData(SST_SIGNATURE_CREATION_TIME, data, true);
    }
}

void SignaturePacket::SetKeyID(KeyIDData& key_id)
{
	key_id_.resize(key_id.size());
	std::move(key_id.begin(), key_id.end(), key_id_.begin());
    
    if (packet_version_ == 4)
    {
        CharDataVector data;
        packet_helper::GetKeyIDData(key_id_, data);
        AddSubpacketData(SST_ISSUER, data, false);
    }
}

void SignaturePacket::SetPublicKeyAlgorithm(PublicKeyAlgorithms public_key_algo)
{
	public_key_algo_ = public_key_algo;
}

void SignaturePacket::SetHashAlgorithm(HashAlgorithms hash_algo)
{
	hash_algo_ = hash_algo;
}

void SignaturePacket::SetDigestStart(std::vector<int>& digest_start)
{
	digest_start_.resize(digest_start.size());
	std::move(digest_start.begin(), digest_start.end(), digest_start_.begin());
}

void SignaturePacket::SetExpiredKeyTime(unsigned int expired_key_time)
{
    expired_key_time_ = expired_key_time;
}

void SignaturePacket::SetExpiredSignatureTime(unsigned int expired_signature_time)
{
    expired_signature_time_ = expired_signature_time;
}

void SignaturePacket::SetPreferedHahAlgos(std::vector<HashAlgorithms> algos)
{
    prefered_hash_algorithms_.assign(algos.begin(), algos.end());
}

void SignaturePacket::SetPreferedChiperAlgos(std::vector<SymmetricKeyAlgorithms> algos)
{
    prefered_chiper_algorithms_.assign(algos.begin(), algos.end());
}

void SignaturePacket::SetPreferedCompressionAlgos(std::vector<CompressionAlgorithms> algos)
{
    prefered_compression_algorithms_.assign(algos.begin(), algos.end());
}

std::vector<HashAlgorithms> SignaturePacket::GetPreferedHahAlgos()
{
    return prefered_hash_algorithms_;
}

std::vector<SymmetricKeyAlgorithms> SignaturePacket::GetPreferedChiperAlgos()
{
    return prefered_chiper_algorithms_;
}

std::vector<CompressionAlgorithms> SignaturePacket::GetPreferedCompressionAlgos()
{
    return prefered_compression_algorithms_;
}

void SignaturePacket::AddMPI(CharDataVector mpi_data)
{
    mpis_.push_back(mpi_data);
}

const CharDataVector SignaturePacket::GetMPI(size_t index)
{
    if ((mpis_.size() != 0) && (index < mpis_.size()))
    {
        return mpis_[index];
    }
    
    return CharDataVector();
}

void SignaturePacket::AddSubpacketData(const SignatureSubpacketType subpacket_type, const CharDataVector& data, bool hashed)
{
    hashed == true ? hashed_subpackets_.push_back(Subpacket(subpacket_type, data)) : unhashed_subpackets_.push_back((Subpacket(subpacket_type, data)));
}

void SignaturePacket::GetDataForHash(CharDataVector& data)
{
    if (GetPacketVersion() == 3)
    {
        data.push_back(0x03);
        data.push_back(signature_type_);

        unsigned int creation_time = GetCreationTime();
        
        data.push_back((creation_time >> 24) & 0xff);
        data.push_back((creation_time >> 16) & 0xff);
        data.push_back((creation_time >> 8) & 0xff);
        data.push_back(creation_time & 0xff);
    }
    else if (GetPacketVersion() == 4)
    {
        CharDataVector hashed_subpackets_data;
        for (Subpacket& subpacket : hashed_subpackets_)
        {
            CharDataVector subpacket_data;
            GetSubpacketBinaryData(subpacket, subpacket_data);
            
            hashed_subpackets_data.insert(hashed_subpackets_data.end(), subpacket_data.begin(), subpacket_data.end());
        }
        
        data.push_back(0x04);
        data.push_back(signature_type_);
        data.push_back(public_key_algo_ );
        data.push_back(hash_algo_);
        
        data.push_back((hashed_subpackets_data.size() >> 8) & 0xff);
        data.push_back(hashed_subpackets_data.size() & 0xff);
        
        data.insert(data.end(), hashed_subpackets_data.begin(), hashed_subpackets_data.end());
    }
}

bool SignaturePacket::GetRawData(CharDataVector& data)
{
    if (GetPacketVersion() == 3)
    {
        return GetRawDataForV3Packet(data);
    }
    else if (GetPacketVersion() == 4)
    {
        return GetRawDataForV4Packet(data);
    }
    
    return false;
}

bool SignaturePacket::GetBinaryData(CharDataVector& data)
{
    CharDataVector temp_data;
    
    GetRawData(temp_data);
    
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

void SignaturePacket::GetSubpacketBinaryData(const Subpacket& subpacket, CharDataVector& subpacket_data)
{
    if ((subpacket.data_.size() + 1 ) < 192)
    {
        subpacket_data.push_back(subpacket.data_.size() + 1);
        subpacket_data.push_back(subpacket.subpacket_type_);
        subpacket_data.insert(subpacket_data.end(), subpacket.data_.begin(), subpacket.data_.end());
    }
    else if (((subpacket.data_.size() + 1) >= 192) && ((subpacket.data_.size() + 1) < 8383))
    {
        int length = static_cast<int>(subpacket.data_.size()) + 1 - 192;
        subpacket_data.push_back((length / 256) + 192);
        subpacket_data.push_back(length % 256);

        
        /*subpacket_data.push_back(((subpacket.data_.size() + 1) >> 8) & 0xff);
        subpacket_data.push_back((subpacket.data_.size() + 1) & 0xff);*/
        
        subpacket_data.push_back(subpacket.subpacket_type_);
        subpacket_data.insert(subpacket_data.end(), subpacket.data_.begin(), subpacket.data_.end());
    }
    else
    {
        subpacket_data.push_back(0xFF);
        subpacket_data.push_back(((subpacket.data_.size() + 1) >> 24) & 0xff);
        subpacket_data.push_back(((subpacket.data_.size() + 1) >> 16) & 0xff);
        subpacket_data.push_back(((subpacket.data_.size() + 1) >> 8) & 0xff);
        subpacket_data.push_back((subpacket.data_.size() + 1) & 0xff);

        subpacket_data.push_back(subpacket.subpacket_type_);
        subpacket_data.insert(subpacket_data.end(), subpacket.data_.begin(), subpacket.data_.end());
    }
}

bool SignaturePacket::GetRawDataForV3Packet(CharDataVector& data)
{
    CharDataVector temp_data;
    temp_data.push_back(3); //packet version
    temp_data.push_back(5); //following hash material
    temp_data.push_back(GetSignatureType());
    
    unsigned int creation_time = GetCreationTime();
    temp_data.push_back((creation_time >> 24) & 0xFF);
    temp_data.push_back((creation_time >> 16) & 0xFF);
    temp_data.push_back((creation_time >> 8) & 0xFF);
    temp_data.push_back(creation_time & 0xFF);
    
    KeyIDData key_id(GetKeyID());
    if (key_id.size() == 2)
    {
        CharDataVector key_id_data;
        packet_helper::GetKeyIDData(key_id, key_id_data);
        temp_data.insert(temp_data.end(), key_id_data.begin(), key_id_data.end());
    }
    else
    {
        data.clear();
        return false;
    }
    
    temp_data.push_back(GetPublicKeyAlgorithm());
    temp_data.push_back(GetHashAlgorithm());
    
    // Set digest start for check
    temp_data.push_back(GetDigestStart()[0]);
    temp_data.push_back(GetDigestStart()[1]);
    
    for (auto iter = mpis_.begin(); iter != mpis_.end(); ++iter)
    {
        if (GetPublicKeyAlgorithm() != PKA_DSA)
        {
            size_t mpi_size = iter->size();
            mpi_size *= 8;
            
            double t = (*iter)[0];
            int bits = packet_helper::log2(t) + 1;
            int delta = 8 - bits;
            mpi_size -= delta;
            
            temp_data.push_back((mpi_size >> 8) & 0xFF);
            temp_data.push_back(mpi_size & 0xFF);
        }
        
        temp_data.insert(temp_data.end(), iter->begin(), iter->end());
    }
    data.insert(data.end(), temp_data.begin(), temp_data.end());
    
    return true;
}

bool SignaturePacket::GetRawDataForV4Packet(CharDataVector& data)
{
    CharDataVector temp_data;
    
    temp_data.push_back(4); //packet version
    temp_data.push_back(GetSignatureType());
    temp_data.push_back(GetPublicKeyAlgorithm());
    temp_data.push_back(GetHashAlgorithm());
    
    CharDataVector hashed_subpackets_data;
    for (Subpacket& subpacket : hashed_subpackets_)
    {
        CharDataVector subpacket_data;
        GetSubpacketBinaryData(subpacket, subpacket_data);
        
        hashed_subpackets_data.insert(hashed_subpackets_data.end(), subpacket_data.begin(), subpacket_data.end());
    }
    
    temp_data.push_back((hashed_subpackets_data.size() >> 8) & 0xff);
    temp_data.push_back(hashed_subpackets_data.size() & 0xff);
    temp_data.insert(temp_data.end(), hashed_subpackets_data.begin(), hashed_subpackets_data.end());

    
    CharDataVector unhashed_subpackets_data;
    for (Subpacket& subpacket : unhashed_subpackets_)
    {
        CharDataVector subpacket_data;
        GetSubpacketBinaryData(subpacket, subpacket_data);
        
        unhashed_subpackets_data.insert(unhashed_subpackets_data.end(), subpacket_data.begin(), subpacket_data.end());
    }
    
    temp_data.push_back((unhashed_subpackets_data.size() >> 8) & 0xff);
    temp_data.push_back(unhashed_subpackets_data.size() & 0xff);
    
    temp_data.insert(temp_data.end(), unhashed_subpackets_data.begin(), unhashed_subpackets_data.end());
    
    // Set digest start for check
    temp_data.push_back(GetDigestStart()[0]);
    temp_data.push_back(GetDigestStart()[1]);
    
    for (auto iter = mpis_.begin(); iter != mpis_.end(); ++iter)
    {
        if (GetPublicKeyAlgorithm() != PKA_DSA)
        {    
            size_t mpi_size = iter->size();
            mpi_size *= 8;
            
            double t = (*iter)[0];
            int bits = packet_helper::log2(t) + 1;
            int delta = 8 - bits;
            mpi_size -= delta;
            
            temp_data.push_back((mpi_size >> 8) & 0xFF);
            temp_data.push_back(mpi_size & 0xFF);
        }
        
        temp_data.insert(temp_data.end(), iter->begin(), iter->end());
    }
    
    data.insert(data.end(), temp_data.begin(), temp_data.end());
    
    return true;
}



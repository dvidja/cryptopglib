//
//  HashAlgorithms.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 14.6.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "HashAlgorithms.h"


namespace
{
    CharDataVector HP_MD5 =         {0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86,
                                                 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, 0x05, 0x00,
                                                 0x04, 0x10};
    
    CharDataVector HP_RIPEMD =      {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x24,
                                                 0x03, 0x02, 0x01, 0x05, 0x00, 0x04, 0x14};
    
    CharDataVector HP_SHA1 =        {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0E,
                                                 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14};
    
    CharDataVector HP_SHA224 =      {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                                                 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
                                                 0x00, 0x04, 0x1C};
    
    CharDataVector HP_SHA256 =      {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                                                 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
                                                0x00, 0x04, 0x20};
    
    CharDataVector HP_SHA384 =      {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                                                 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
                                                 0x00, 0x04, 0x30};
    
    CharDataVector HP_SHA512 =      {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                                                 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
                                                 0x00, 0x04, 0x40};
}

namespace  crypto
{
    /// MD5 implementation
    bool Md5::Hash(const CharDataVector& source, CharDataVector& dest)
    {
        dest.resize(MD5_DIGEST_LENGTH);
        if (!MD5(&source[0], source.size(), &dest[0]))
        {
            dest.clear();
        }
        
        return true;
    }
    
    int Md5::GetDigestLength()
    {
        return MD5_DIGEST_LENGTH;
    }

    const CharDataVector& Md5::GetHashPrefix()
    {
        return HP_MD5;
    }
    
    void Md5::Init()
    {
        MD5_Init(&context_);
    }
    
    void Md5::Update(const CharDataVector& data)
    {
        MD5_Update(&context_, (void*)&data[0], data.size());
    }
    
    void Md5::Final(CharDataVector& result_hash)
    {
        result_hash.resize(GetDigestLength());
        MD5_Final(&result_hash[0], &context_);
    }
    
    std::string Md5::GetHashAlgorithmName()
    {
        return "MD5";
    }
    
    /// SHA1 implementation
    bool Sha1::Hash(const CharDataVector& source, CharDataVector& dest)
    {
        dest.resize(SHA_DIGEST_LENGTH);
		if (source.empty())
		{
			if (!SHA1(nullptr, 0, &dest[0]))
			{
				dest.clear();
			}
			return true;
		}
        if (!SHA1(&source[0], source.size(), &dest[0]))
        {
            dest.clear();
        }
        
        return true;
    }
    
    int Sha1::GetDigestLength()
    {
        return SHA_DIGEST_LENGTH;
    }
    
    const CharDataVector& Sha1::GetHashPrefix()
    {
        return HP_SHA1;
    }
    
    void Sha1::Init()
    {
        SHA1_Init(&context_);
    }
    
    void Sha1::Update(const CharDataVector& data)
    {
        SHA1_Update(&context_, (void*)&data[0], data.size());
    }
    
    void Sha1::Final(CharDataVector& result_hash)
    {
        result_hash.resize(GetDigestLength());
        SHA1_Final(&result_hash[0], &context_);
    }
    
    std::string Sha1::GetHashAlgorithmName()
    {
        return "SHA1";
    }
    
    /// RipeMD implementation
    bool RipeMD::Hash(const CharDataVector& source, CharDataVector& dest)
    {
        dest.resize(RIPEMD160_DIGEST_LENGTH);
        if (!RIPEMD160(&source[0], source.size(), &dest[0]))
        {
            dest.clear();
        }
        
        return true;
    }
    
    int RipeMD::GetDigestLength()
    {
        return RIPEMD160_DIGEST_LENGTH;
    }

    const CharDataVector& RipeMD::GetHashPrefix()
    {
        return HP_RIPEMD;
    }
    
    void RipeMD::Init()
    {
        RIPEMD160_Init(&context_);
    }
    
    void RipeMD::Update(const CharDataVector& data)
    {
        RIPEMD160_Update(&context_, (void*)&data[0], data.size());
    }
    
    void RipeMD::Final(CharDataVector& result_hash)
    {
        result_hash.resize(GetDigestLength());
        RIPEMD160_Final(&result_hash[0], &context_);
    }
    
    std::string RipeMD::GetHashAlgorithmName()
    {
        return "RIPEMD160";
    }

    /// SHA256 implementation
    bool Sha256::Hash(const CharDataVector& source, CharDataVector& dest)
    {
        dest.resize(SHA256_DIGEST_LENGTH);
		if (source.empty()) return true;
        if (!SHA256(&source[0], source.size(), &dest[0]))
        {
            dest.clear();
        }
        
        return true;
    }
    
    int Sha256::GetDigestLength()
    {
        return SHA256_DIGEST_LENGTH;
    }

    const CharDataVector& Sha256::GetHashPrefix()
    {
        return HP_SHA256;
    }
    
    void Sha256::Init()
    {
        SHA256_Init(&context_);
    }
    
    void Sha256::Update(const CharDataVector& data)
    {
        SHA256_Update(&context_, (void*)&data[0], data.size());
    }
    
    void Sha256::Final(CharDataVector& result_hash)
    {
        result_hash.resize(GetDigestLength());
        SHA256_Final(&result_hash[0], &context_);
    }
    
    std::string Sha256::GetHashAlgorithmName()
    {
        return "SHA256";
    }
    
    /// SHA384 implementation
    bool Sha384::Hash(const CharDataVector& source, CharDataVector& dest)
    {
        dest.resize(SHA384_DIGEST_LENGTH);
        if (!SHA384(&source[0], source.size(), &dest[0]))
        {
            dest.clear();
        }
        
        return true;
    }
    
    int Sha384::GetDigestLength()
    {
        return SHA384_DIGEST_LENGTH;
    }

    const CharDataVector& Sha384::GetHashPrefix()
    {
        return HP_SHA384;
    }
    
    void Sha384::Init()
    {
        SHA384_Init(&context_);
    }
    
    void Sha384::Update(const CharDataVector& data)
    {
        SHA384_Update(&context_, (void*)&data[0], data.size());
    }
    
    void Sha384::Final(CharDataVector& result_hash)
    {
        result_hash.resize(GetDigestLength());
        SHA384_Final(&result_hash[0], &context_);
    }
    
    std::string Sha384::GetHashAlgorithmName()
    {
        return "SHA384";
    }
    
    /// SHA512 implementation
    bool Sha512::Hash(const CharDataVector& source, CharDataVector& dest)
    {
        dest.resize(SHA512_DIGEST_LENGTH);
        if (!SHA512(&source[0], source.size(), &dest[0]))
        {
            dest.clear();
        }
        
        return true;
    }
    
    int Sha512::GetDigestLength()
    {
        return SHA512_DIGEST_LENGTH;
    }

    const CharDataVector& Sha512::GetHashPrefix()
    {
        return HP_SHA512;
    }
    
    void Sha512::Init()
    {
        SHA512_Init(&context_);
    }
    
    void Sha512::Update(const CharDataVector& data)
    {
        SHA512_Update(&context_, (void*)&data[0], data.size());
    }
    
    void Sha512::Final(CharDataVector& result_hash)
    {
        result_hash.resize(GetDigestLength());
        SHA512_Final(&result_hash[0], &context_);
    }
    
    std::string Sha512::GetHashAlgorithmName()
    {
        return "SHA512";
    }
    
    /// SHA224 implementation
    bool Sha224::Hash(const CharDataVector& source, CharDataVector& dest)
    {
        dest.resize(SHA224_DIGEST_LENGTH);
        if (!SHA224(&source[0], source.size(), &dest[0]))
        {
            dest.clear();
        }
        
        return true;
    }
    
    int Sha224::GetDigestLength()
    {
        return SHA224_DIGEST_LENGTH;
    }
    
    const CharDataVector& Sha224::GetHashPrefix()
    {
        return HP_SHA224;
    }
    
    void Sha224::Init()
    {
        SHA224_Init(&context_);
    }
    
    void Sha224::Update(const CharDataVector& data)
    {
        SHA224_Update(&context_, (void*)&data[0], data.size());
    }
    
    void Sha224::Final(CharDataVector& result_hash)
    {
        result_hash.resize(GetDigestLength());
        SHA224_Final(&result_hash[0], &context_);
    }
    
    std::string Sha224::GetHashAlgorithmName()
    {
        return "SHA224";
    }
    
    HashAlgorithmPtr GetHashImpl(HashAlgorithms algo)
    {
        HashAlgorithmPtr hash_algo_ptr(nullptr);
        switch (algo)
        {
            case HA_NO_HASH:
                break;
            case HA_MD5:
                hash_algo_ptr = std::make_unique<Md5>();
                break;
            case HA_SHA1:
                hash_algo_ptr = std::make_unique<Sha1>();
                break;
            case HA_RIPE_MD:
                hash_algo_ptr = std::make_unique<RipeMD>();
                break;
            case HA_SHA256:
                hash_algo_ptr = std::make_unique<Sha256>();
                break;
            case HA_SHA384:
                hash_algo_ptr = std::make_unique<Sha384>();
                break;
            case HA_SHA512:
                hash_algo_ptr = std::make_unique<Sha512>();
                break;
            case HA_SHA224:
                hash_algo_ptr = std::make_unique<Sha224>();
                break;
        }
        
        return hash_algo_ptr;
    }
    
}

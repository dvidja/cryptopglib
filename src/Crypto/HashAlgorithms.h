//
//  HashAlgorithms.h
//  cryptopg
//
//  Created by Anton Sarychev on 14.6.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_HashAlgorithms_h
#define cryptopg_HashAlgorithms_h

#include <openssl/sha.h>
#include "openssl/md5.h"
#include "openssl/ripemd.h"

#include <string>

#include "../PGPData/PGPDataTypes.h"

enum HashAlgorithms
{
    HA_NO_HASH = 0,
    HA_MD5 = 1,
    HA_SHA1 = 2,
    HA_RIPE_MD = 3,
    
    HA_SHA256 = 8,
    HA_SHA384 = 9,
    HA_SHA512 = 10,
    HA_SHA224 = 11,
};

namespace crypto
{
    class HashAlgorithm
    {
    public:
        virtual bool Hash(const CharDataVector& source, CharDataVector& dest) = 0;
        virtual int GetDigestLength() = 0;
        virtual const CharDataVector& GetHashPrefix() = 0;
        virtual void Init() = 0;
        virtual void Update(const CharDataVector& data) = 0;
        virtual void Final(CharDataVector& result_hash) = 0;
        virtual std::string GetHashAlgorithmName() = 0;

        virtual ~HashAlgorithm() {}
    };
    
    typedef std::unique_ptr<HashAlgorithm> HashAlgorithmPtr;
    
    class Md5 : public HashAlgorithm
    {
    public:
        virtual bool Hash(const CharDataVector& source, CharDataVector& dest);
        virtual int GetDigestLength();
        virtual const CharDataVector& GetHashPrefix();
        virtual void Init();
        virtual void Update(const CharDataVector& data);
        virtual void Final(CharDataVector& result_hash);
        virtual std::string GetHashAlgorithmName();
        
    private:
        MD5_CTX context_;

    };
        
    class Sha1 : public HashAlgorithm
    {
    public:
        virtual bool Hash(const CharDataVector& source, CharDataVector& dest);
        virtual int GetDigestLength();
        virtual const CharDataVector& GetHashPrefix();
        virtual void Init();
        virtual void Update(const CharDataVector& data);
        virtual void Final(CharDataVector& result_hash);
        virtual std::string GetHashAlgorithmName();
        
    private:
        SHA_CTX context_;
    };
    
    class RipeMD : public HashAlgorithm
    {
    public:
        virtual bool Hash(const CharDataVector& source, CharDataVector& dest);
        virtual int GetDigestLength();
        virtual const CharDataVector& GetHashPrefix();
        virtual void Init();
        virtual void Update(const CharDataVector& data);
        virtual void Final(CharDataVector& result_hash);
        virtual std::string GetHashAlgorithmName();
    
    private:
        RIPEMD160_CTX context_;
    };

    class Sha256 : public HashAlgorithm
    {
    public:
        virtual bool Hash(const CharDataVector& source, CharDataVector& dest);
        virtual int GetDigestLength();
        virtual const CharDataVector& GetHashPrefix();
        virtual void Init();
        virtual void Update(const CharDataVector& data);
        virtual void Final(CharDataVector& result_hash);
        virtual std::string GetHashAlgorithmName();
        
    private:
        SHA256_CTX context_;
    };

    class Sha384 : public HashAlgorithm
    {
    public:
        virtual bool Hash(const CharDataVector& source, CharDataVector& dest);
        virtual int GetDigestLength();
        virtual const CharDataVector& GetHashPrefix();
        virtual void Init();
        virtual void Update(const CharDataVector& data);
        virtual void Final(CharDataVector& result_hash);
        virtual std::string GetHashAlgorithmName();
        
    private:
        SHA512_CTX context_;
    };

    class Sha512 : public HashAlgorithm
    {
    public:
        virtual bool Hash(const CharDataVector& source, CharDataVector& dest);
        virtual int GetDigestLength();
        virtual const CharDataVector& GetHashPrefix();
        virtual void Init();
        virtual void Update(const CharDataVector& data);
        virtual void Final(CharDataVector& result_hash);
        virtual std::string GetHashAlgorithmName();
        
    private:
        SHA512_CTX context_;
    };

    class Sha224 : public HashAlgorithm
    {
    public:
        virtual bool Hash(const CharDataVector& source, CharDataVector& dest);
        virtual int GetDigestLength();
        virtual const CharDataVector& GetHashPrefix();
        virtual void Init();
        virtual void Update(const CharDataVector& data);
        virtual void Final(CharDataVector& result_hash);
        virtual std::string GetHashAlgorithmName();
        
    private:
        SHA256_CTX context_;
    };
    
    HashAlgorithmPtr GetHashImpl(HashAlgorithms algo);
}

#endif

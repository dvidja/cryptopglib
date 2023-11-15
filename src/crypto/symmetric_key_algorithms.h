//
//  SymmetricKeyAlgorithms.h
//  cryptopg
//
//  Created by Anton Sarychev on 13.6.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_SymmetricKeyAlgorithms_h
#define cryptopg_SymmetricKeyAlgorithms_h
#include <memory>
#include "../pgp_data/pgp_data_types.h"


enum SymmetricKeyAlgorithms
{
    SKA_PLAIN_TEXT = 0,
    SKA_IDEA = 1,
    SKA_TRIPLE_DES = 2,
    SKA_CAST5 = 3,
    SKA_BLOWFISH = 4,
    
    SKA_AES_128 = 7,
    SKA_AES_192 = 8,
    SKA_AES_256 = 9,
    SKA_TWOFISH = 10, /// ??? 
};

namespace crypto
{
    class SymmetricKeyAlgorithm
    {
    public:
        virtual ~SymmetricKeyAlgorithm() {};

        virtual int GetChiperBlockSize() = 0;
        virtual int GetKeyLength() = 0;
        
        virtual bool EncryptBlock(const CharDataVector& input_data,
                                      const CharDataVector& session_key,
                                      CharDataVector& result_data) = 0;
        
        virtual bool DecryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data) = 0;

        
        virtual bool EncryptInCFBMode(const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             CharDataVector& initial_vector,
                             CharDataVector& result_data) = 0;
        
        virtual bool DecryptInCFBMode(const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             const CharDataVector& initial_vector,
                             CharDataVector& result_data) = 0;
        
        bool EncryptInOpenPGPCFBMode(const CharDataVector& input_data,
                                     const CharDataVector& session_key,
                                     CharDataVector& prefix_data,
                                     CharDataVector& result_data,
                                     bool flag = true);
        
        bool DecryptInOpenPGPCFBMode(const CharDataVector& input_data,
                                     const CharDataVector& session_key,
                                     CharDataVector& result_data,
                                     bool flag = true);


    };
    
    typedef std::unique_ptr<SymmetricKeyAlgorithm> SymmetricKeyAlgorithmPtr;
    
    
    class Idea : public SymmetricKeyAlgorithm
    {
    public:        
        virtual int GetChiperBlockSize();
        virtual int GetKeyLength();
        
        virtual bool EncryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data);
        
        virtual bool DecryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data);

        virtual bool EncryptInCFBMode(const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             CharDataVector& initial_vector,
                             CharDataVector& result_data);
        
        virtual bool DecryptInCFBMode(const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             const CharDataVector& initial_vector,
                             CharDataVector& result_data);

    };
    
    class TripleDes : public SymmetricKeyAlgorithm
    {
    public:
        virtual int GetChiperBlockSize();
        virtual int GetKeyLength();
        
        virtual bool EncryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data);
        
        virtual bool DecryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data);
        
        virtual bool EncryptInCFBMode(const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             CharDataVector& initial_vector,
                             CharDataVector& result_data);

        virtual bool DecryptInCFBMode(const CharDataVector& initial_vector,
                             const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             CharDataVector& result_data);
    };

    class Cast5 : public SymmetricKeyAlgorithm
    {
    public:
        virtual int GetChiperBlockSize();
        virtual int GetKeyLength();
        
        virtual bool EncryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data);
        
        virtual bool DecryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data);
        
        virtual bool EncryptInCFBMode(const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             CharDataVector& initial_vector,
                             CharDataVector& result_data);
        
        virtual bool DecryptInCFBMode(const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             const CharDataVector& initial_vector,
                             CharDataVector& result_data);
    };

    class BlowFish : public SymmetricKeyAlgorithm
    {
    public:
        virtual int GetChiperBlockSize();
        virtual int GetKeyLength();
        
        virtual bool EncryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data);
        
        virtual bool DecryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data);

        
        virtual bool EncryptInCFBMode(const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             CharDataVector& initial_vector,
                             CharDataVector& result_data);
        
        virtual bool DecryptInCFBMode(const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             const CharDataVector& initial_vector,
                             CharDataVector& result_data);

    };

    class AES128 : public SymmetricKeyAlgorithm
    {
    public:
        virtual int GetChiperBlockSize();
        virtual int GetKeyLength();
        
        virtual bool EncryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data);
        
        virtual bool DecryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data);
        
        virtual bool EncryptInCFBMode(const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             CharDataVector& initial_vector,
                             CharDataVector& result_data);
        
        virtual bool DecryptInCFBMode(const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             const CharDataVector& initial_vector,
                             CharDataVector& result_data);
    };
    
    class AES192 : public SymmetricKeyAlgorithm
    {
    public:
        virtual int GetChiperBlockSize();
        virtual int GetKeyLength();
        
        virtual bool EncryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data);
        
        virtual bool DecryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data);
        
        virtual bool EncryptInCFBMode(const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             CharDataVector& initial_vector,
                             CharDataVector& result_data);
        
        virtual bool DecryptInCFBMode(const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             const CharDataVector& initial_vector,
                             CharDataVector& result_data);

    };

    class AES256 : public SymmetricKeyAlgorithm
    {
    public:
        virtual int GetChiperBlockSize();
        virtual int GetKeyLength();
        
        virtual bool EncryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data);
        
        virtual bool DecryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data);
        
        virtual bool EncryptInCFBMode(const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             CharDataVector& initial_vector,
                             CharDataVector& result_data);
        
        virtual bool DecryptInCFBMode(const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             const CharDataVector& initial_vector,
                             CharDataVector& result_data);
    };

    class TwoFish : public SymmetricKeyAlgorithm
    {
    public:
        virtual int GetChiperBlockSize();
        virtual int GetKeyLength();
        
        virtual bool EncryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data);
        
        virtual bool DecryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data);
        
        virtual bool EncryptInCFBMode(const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             CharDataVector& initial_vector,
                             CharDataVector& result_data);
        
        virtual bool DecryptInCFBMode(const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             const CharDataVector& initial_vector,
                             CharDataVector& result_data);
    };
    
    
    SymmetricKeyAlgorithmPtr GetSymmetricKeyAlgorithm(SymmetricKeyAlgorithms algo);
}

#endif

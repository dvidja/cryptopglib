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
#include "cryptopglib/symmetric_key_algorithms.h"

namespace cryptopglib::crypto {
    class SymmetricKeyAlgorithm
    {
    public:
        virtual ~SymmetricKeyAlgorithm() = default;

        virtual int GetCipherBlockSize() = 0;
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
        int GetCipherBlockSize() override;
        int GetKeyLength() override;

        bool EncryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data) override;

        bool DecryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data) override;

        bool EncryptInCFBMode(const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             CharDataVector& initial_vector,
                             CharDataVector& result_data) override;

        bool DecryptInCFBMode(const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             const CharDataVector& initial_vector,
                             CharDataVector& result_data) override;

    };

    class TripleDes : public SymmetricKeyAlgorithm
    {
    public:
        int GetCipherBlockSize() override;
        int GetKeyLength() override;

        bool EncryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data) override;

        bool DecryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data) override;

        bool EncryptInCFBMode(const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             CharDataVector& initial_vector,
                             CharDataVector& result_data) override;

        bool DecryptInCFBMode(const CharDataVector& initial_vector,
                             const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             CharDataVector& result_data) override;
    };

    class Cast5 : public SymmetricKeyAlgorithm
    {
    public:
        int GetCipherBlockSize() override;
        int GetKeyLength() override;

        bool EncryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data) override;

        bool DecryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data) override;

        bool EncryptInCFBMode(const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             CharDataVector& initial_vector,
                             CharDataVector& result_data) override;

        bool DecryptInCFBMode(const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             const CharDataVector& initial_vector,
                             CharDataVector& result_data) override;
    };

    class BlowFish : public SymmetricKeyAlgorithm
    {
    public:
        int GetCipherBlockSize() override;
        int GetKeyLength() override;

        bool EncryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data) override;

        bool DecryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data) override;


        bool EncryptInCFBMode(const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             CharDataVector& initial_vector,
                             CharDataVector& result_data) override;

        bool DecryptInCFBMode(const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             const CharDataVector& initial_vector,
                             CharDataVector& result_data) override;

    };

    class AES128 : public SymmetricKeyAlgorithm
    {
    public:
        int GetCipherBlockSize() override;
        int GetKeyLength() override;

        bool EncryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data) override;

        bool DecryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data) override;

        bool EncryptInCFBMode(const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             CharDataVector& initial_vector,
                             CharDataVector& result_data) override;

        bool DecryptInCFBMode(const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             const CharDataVector& initial_vector,
                             CharDataVector& result_data) override;
    };

    class AES192 : public SymmetricKeyAlgorithm
    {
    public:
        int GetCipherBlockSize() override;
        int GetKeyLength() override;

        bool EncryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data) override;

        bool DecryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data) override;

        bool EncryptInCFBMode(const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             CharDataVector& initial_vector,
                             CharDataVector& result_data) override;

        bool DecryptInCFBMode(const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             const CharDataVector& initial_vector,
                             CharDataVector& result_data) override;

    };

    class AES256 : public SymmetricKeyAlgorithm
    {
    public:
        int GetCipherBlockSize() override;
        int GetKeyLength() override;

        bool EncryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data) override;

        bool DecryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data) override;

        bool EncryptInCFBMode(const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             CharDataVector& initial_vector,
                             CharDataVector& result_data) override;

        bool DecryptInCFBMode(const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             const CharDataVector& initial_vector,
                             CharDataVector& result_data) override;
    };

    class TwoFish : public SymmetricKeyAlgorithm
    {
    public:
        int GetCipherBlockSize() override;
        int GetKeyLength() override;

        bool EncryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data) override;

        bool DecryptBlock(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data) override;

        bool EncryptInCFBMode(const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             CharDataVector& initial_vector,
                             CharDataVector& result_data) override;

        bool DecryptInCFBMode(const CharDataVector& input_data,
                             const CharDataVector& session_key,
                             const CharDataVector& initial_vector,
                             CharDataVector& result_data) override;
    };


    SymmetricKeyAlgorithmPtr GetSymmetricKeyAlgorithm(SymmetricKeyAlgorithms algo);
}

#endif

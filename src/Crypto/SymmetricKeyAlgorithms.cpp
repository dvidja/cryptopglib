//
//  SymmetricKeyAlgorithms.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 6.7.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "SymmetricKeyAlgorithms.h"
extern "C" {
#include <openssl/idea.h>
#include <openssl/des.h>
#include <openssl/cast.h>
#include <openssl/blowfish.h>
#include <openssl/aes.h>
}

#include <string>
#include <algorithm>

namespace
{
    void XORData(const CharDataVector vector1, const CharDataVector vector2, CharDataVector& result)
    {
        result.resize(std::min(vector1.size(), vector2.size()), 0);
        for(int i = 0; i < result.size(); ++i)
        {
            result[i] = vector1[i] ^ vector2[i];
        }
    }
    
    void GetDataPart(const CharDataVector& intput_data, size_t start_pos, size_t length, CharDataVector& result_data)
    {
        if (intput_data.size() >= start_pos + length)
        {
            result_data.assign(intput_data.begin() + start_pos, intput_data.begin() + start_pos + length);
        }
        else
        {
            result_data.assign(intput_data.begin() + start_pos, intput_data.end());
        }
    }
}

namespace crypto
{
    
    bool SymmetricKeyAlgorithm::EncryptInOpenPGPCFBMode(const CharDataVector& input_data,
                                 const CharDataVector& session_key,
                                 CharDataVector& prefix_data,
                                 CharDataVector& result_data,
                                 bool flag)

    {
        unsigned int block_size = GetChiperBlockSize();
        
        // 1
        CharDataVector FR(block_size, 0);
        // 2
        CharDataVector FRE(FR.size(), 0);
        EncryptBlock(FR, session_key, FRE);
        // 3
        XORData(FRE, prefix_data, FRE);
        result_data.assign(FRE.begin(), FRE.end());
        // 4
        FR.assign(result_data.begin(), result_data.end());
        // 5
        FRE.resize(FR.size(), 0);
        EncryptBlock(FR, session_key, FRE);
        // 6
        XORData(CharDataVector(FRE.begin(), FRE.begin() + 2), CharDataVector(prefix_data.end() - 2, prefix_data.end()), FRE);
        result_data.insert(result_data.end(), FRE.begin(), FRE.end());
        // 7
        if (flag)
        {
            FR.assign(result_data.begin() + 2, result_data.begin() + 2 + block_size);
            // 8
            FRE.resize(FR.size(), 0);
            EncryptBlock(FR, session_key, FRE);
            // 9
            GetDataPart(input_data, 0, block_size, FR);
            XORData(FRE, FR, FRE);
            result_data.insert(result_data.end(), FRE.begin(), FRE.end());
            
            unsigned int x = block_size;
            
            while (x < input_data.size())
            {
                // 10
                FR.assign(result_data.begin() + x + 2, result_data.begin() + x + 2 + block_size);
                // 11
                FRE.resize(FR.size(), 0);
                EncryptBlock(FR, session_key, FRE);
                // 12
                GetDataPart(input_data, x, block_size, FR);
                XORData(FRE, FR, FRE);
                result_data.insert(result_data.end(), FRE.begin(), FRE.end());
                
                x += block_size;
            }
        }
        else
        {
            // 8
            FRE.resize(FR.size(), 0);
            //EncryptBlock(FR, session_key, FRE);
            // 9
            GetDataPart(FRE, 2, block_size - 2, FR);
            GetDataPart(input_data, 0, block_size, FRE);
            XORData(FR, FRE, FRE);
            result_data.insert(result_data.end(), FRE.begin(), FRE.end());

            GetDataPart(result_data, 0, block_size << 1, FRE);
            result_data.assign(FRE.begin(), FRE.end());

            unsigned int x = block_size;
            while (x < input_data.size())
            {
                // 10
                GetDataPart(result_data, x, block_size, FR);
                // 11
                FRE.resize(FR.size(), 0);
                EncryptBlock(FR, session_key, FRE);
                // 12
                GetDataPart(input_data, x - 2, block_size, FR);
                XORData(FRE, FR, FRE);
                result_data.insert(result_data.end(), FRE.begin(), FRE.end());

                x += block_size;
            }
        }
        
        return true;
    }
    
    bool SymmetricKeyAlgorithm::DecryptInOpenPGPCFBMode(const CharDataVector& input_data,
                                  const CharDataVector& session_key,
                                  CharDataVector& result_data,
                                  bool flag)
    {
        unsigned int block_size = GetChiperBlockSize();
        
        // 1
        CharDataVector FR(block_size, 0);

        // 2
        CharDataVector FRE(block_size, 0);
        EncryptBlock(FR, session_key, FRE);
        
        // 4
        GetDataPart(input_data, 0, block_size, FR);
        
        // 3
        CharDataVector prefix(block_size, 0);
        XORData(FRE, FR, prefix);
        
        // 5
        FRE.resize(block_size, 0);
        EncryptBlock(FR, session_key, FRE);

        CharDataVector check;
        GetDataPart(FRE, 0, 2, FR);
        GetDataPart(input_data, block_size, 2, check);
        XORData(FR, check, check);
        
        // 6
        if (!std::equal(prefix.end() - 2, prefix.end(), check.begin()))
        {
            return false;
        }
        
        CharDataVector P;
        
        unsigned int x = flag ? 2 : 0;
        
        while ((x + block_size) < input_data.size())
        {
            GetDataPart(input_data, x, block_size, FR);
            XORData(FRE, FR, FRE);
            P.insert(P.end(), FRE.begin(), FRE.end());

            EncryptBlock(FR, session_key, FRE);
            x += block_size;
        }
        
        GetDataPart(input_data, x, block_size, FR);
        XORData(FRE, FR, FRE);
        P.insert(P.end(), FRE.begin(), FRE.end());

        
        result_data.assign(prefix.begin(), prefix.end());
        result_data.insert(result_data.end(), prefix.end() - 2, prefix.end());
        result_data.insert(result_data.end(), P.begin() + block_size, P.end());
        
        return true;
    }
    
    int Idea::GetChiperBlockSize()
    {
        return IDEA_BLOCK;
    }
    
    int Idea::GetKeyLength()
    {
        return IDEA_KEY_LENGTH;
    }
    
    bool Idea::EncryptBlock(const CharDataVector& input_data,
                            const CharDataVector& session_key,
                            CharDataVector& result_data)
    {
        IDEA_KEY_SCHEDULE key;
		//TODO: FIX IDEA
        //idea_set_encrypt_key(&session_key[0], &key);
        
        result_data.resize(input_data.size());
        
		//TODO: FIX IDEA
        //idea_ecb_encrypt(&input_data[0], &result_data[0], &key);

        return true;
    }
    
    bool Idea::DecryptBlock(const CharDataVector& input_data,
                            const CharDataVector& session_key,
                            CharDataVector& result_data)
    {
        IDEA_KEY_SCHEDULE encrypt_key;
		//TODO: FIX IDEA
        //idea_set_encrypt_key(&session_key[0], &encrypt_key);
        IDEA_KEY_SCHEDULE decrypt_key;
		//TODO: FIX IDEA
        //idea_set_decrypt_key(&encrypt_key, &decrypt_key);
        
        result_data.resize(input_data.size());
        
		//TODO: FIX IDEA
        //idea_ecb_encrypt(&input_data[0], &result_data[0], &decrypt_key);

        return true;
    }
    
    bool Idea::EncryptInCFBMode(const CharDataVector& input_data,
                         const CharDataVector& session_key,
                         CharDataVector& initial_vector,
                         CharDataVector& result_data)
    {
        result_data.resize(input_data.size());
        CharDataVector ivec(initial_vector);
        
        IDEA_KEY_SCHEDULE idea_key;
		//TODO: FIX IDEA
        //idea_set_encrypt_key(&session_key[0], &idea_key);
        
        int num = 0;
        //TODO: FIX IDEA
		//idea_cfb64_encrypt(&input_data[0], &result_data[0], input_data.size(), &idea_key, &ivec[0], &num, IDEA_ENCRYPT);
        
        return true;
    }
    
    bool Idea::DecryptInCFBMode(const CharDataVector& input_data,
                       const CharDataVector& session_key,
                       const CharDataVector& initial_vector,
                       CharDataVector& result_data)
    {
        result_data.resize(input_data.size());
        CharDataVector ivec(initial_vector);
        
        IDEA_KEY_SCHEDULE idea_key;
		//TODO: FIX IDEA
        //idea_set_encrypt_key(&session_key[0], &idea_key);
        
        int num = 0;
		//TODO: FIX IDEA
        //idea_cfb64_encrypt(&input_data[0], &result_data[0], input_data.size(), &idea_key, &ivec[0], &num, IDEA_DECRYPT);

        return true;
    }
    
    int TripleDes::GetChiperBlockSize()
    {
        return 8;
    }
    
    int TripleDes::GetKeyLength()
    {
        return 24;
    }
    
    bool TripleDes::EncryptBlock(const CharDataVector& input_data,
                              const CharDataVector& session_key,
                              CharDataVector& result_data)
    {
        DES_key_schedule des_key1;
        const_DES_cblock des_cblock1 = {session_key[0], session_key[1], session_key[2], session_key[3], session_key[4], session_key[5], session_key[6], session_key[7]};
        DES_set_key_unchecked(&des_cblock1, &des_key1);
        
        DES_key_schedule des_key2;
        const_DES_cblock des_cblock2 = {session_key[8], session_key[9], session_key[10], session_key[11], session_key[12], session_key[13], session_key[14], session_key[15]};
        DES_set_key_unchecked(&des_cblock2, &des_key2);
        
        DES_key_schedule des_key3;
        const_DES_cblock des_cblock3 = {session_key[16], session_key[17], session_key[18], session_key[19], session_key[20], session_key[21], session_key[22], session_key[23]};
        DES_set_key_unchecked(&des_cblock3, &des_key3);
        
        result_data.resize(input_data.size());
        
        const_DES_cblock des_cblock_input = {input_data[0], input_data[1], input_data[2], input_data[3], input_data[4], input_data[5], input_data[6], input_data[7]};
        const_DES_cblock des_cblock_result;
        DES_ecb3_encrypt(&des_cblock_input, &des_cblock_result, &des_key1, &des_key2, &des_key3, DES_ENCRYPT);
        
        result_data = {des_cblock_result[0], des_cblock_result[1], des_cblock_result[2], des_cblock_result[3], des_cblock_result[4], des_cblock_result[5], des_cblock_result[6], des_cblock_result[7]};

        return true;
    }
    
    bool TripleDes::DecryptBlock(const CharDataVector& input_data,
                              const CharDataVector& session_key,
                              CharDataVector& result_data)
    {
        DES_key_schedule des_key1;
        const_DES_cblock des_cblock1 = {session_key[0], session_key[1], session_key[2], session_key[3], session_key[4], session_key[5], session_key[6], session_key[7]};
        DES_set_key_unchecked(&des_cblock1, &des_key1);
        
        DES_key_schedule des_key2;
        const_DES_cblock des_cblock2 = {session_key[8], session_key[9], session_key[10], session_key[11], session_key[12], session_key[13], session_key[14], session_key[15]};
        DES_set_key_unchecked(&des_cblock2, &des_key2);
        
        DES_key_schedule des_key3;
        const_DES_cblock des_cblock3 = {session_key[16], session_key[17], session_key[18], session_key[19], session_key[20], session_key[21], session_key[22], session_key[23]};
        DES_set_key_unchecked(&des_cblock3, &des_key3);
        
        result_data.resize(input_data.size());
        
        const_DES_cblock des_cblock_input = {input_data[0], input_data[1], input_data[2], input_data[3], input_data[4], input_data[5], input_data[6], input_data[7]};
        const_DES_cblock des_cblock_result;
        DES_ecb3_encrypt(&des_cblock_input, &des_cblock_result, &des_key1, &des_key2, &des_key3, DES_DECRYPT);
        
        result_data = {des_cblock_result[0], des_cblock_result[1], des_cblock_result[2], des_cblock_result[3], des_cblock_result[4], des_cblock_result[5], des_cblock_result[6], des_cblock_result[7]};
        
        return true;
    }

    
    bool TripleDes::EncryptInCFBMode(const CharDataVector& input_data,
                            const CharDataVector& session_key,
                            CharDataVector& initial_vector,
                            CharDataVector& result_data)
    {
        DES_key_schedule des_key1;
        const_DES_cblock des_cblock1 = {session_key[0], session_key[1], session_key[2], session_key[3], session_key[4], session_key[5], session_key[6], session_key[7]};
        DES_set_key_unchecked(&des_cblock1, &des_key1);
        
        DES_key_schedule des_key2;
        const_DES_cblock des_cblock2 = {session_key[8], session_key[9], session_key[10], session_key[11], session_key[12], session_key[13], session_key[14], session_key[15]};
        DES_set_key_unchecked(&des_cblock2, &des_key2);
        
        DES_key_schedule des_key3;
        const_DES_cblock des_cblock3 = {session_key[16], session_key[17], session_key[18], session_key[19], session_key[20], session_key[21], session_key[22], session_key[23]};
        DES_set_key_unchecked(&des_cblock3, &des_key3);
        
        result_data.resize(input_data.size());
        
        const_DES_cblock ivec_cblock = {0};
        for (int i = 0; i < initial_vector.size(); ++i)
        {
            ivec_cblock[i] = initial_vector[i];
        }

        int num = 0;
        DES_ede3_cfb64_encrypt(&input_data[0], &result_data[0], input_data.size(), &des_key1, &des_key2, &des_key3, &ivec_cblock, &num, DES_ENCRYPT);
        
        return true;
    }
    
    bool TripleDes::DecryptInCFBMode(const CharDataVector& input_data,
                            const CharDataVector& session_key,
                            const CharDataVector& initial_vector,
                            CharDataVector& result_data)
    {        
        DES_key_schedule des_key1;
        const_DES_cblock des_cblock1 = {session_key[0], session_key[1], session_key[2], session_key[3], session_key[4], session_key[5], session_key[6], session_key[7]};
        DES_set_key_unchecked(&des_cblock1, &des_key1);
        
        DES_key_schedule des_key2;
        const_DES_cblock des_cblock2 = {session_key[8], session_key[9], session_key[10], session_key[11], session_key[12], session_key[13], session_key[14], session_key[15]};
        DES_set_key_unchecked(&des_cblock2, &des_key2);
        
        DES_key_schedule des_key3;
        const_DES_cblock des_cblock3 = {session_key[16], session_key[17], session_key[18], session_key[19], session_key[20], session_key[21], session_key[22], session_key[23]};
        DES_set_key_unchecked(&des_cblock3, &des_key3);
        
        result_data.resize(input_data.size());
        
        const_DES_cblock ivec_cblock = {0};
        for (int i = 0; i < initial_vector.size(); ++i)
        {
            ivec_cblock[i] = initial_vector[i];
        }
        
        int num = 0;
        DES_ede3_cfb64_encrypt(&input_data[0], &result_data[0], input_data.size(), &des_key1, &des_key2, &des_key3, &ivec_cblock, &num, DES_DECRYPT);
        
        return true;
    }
    
    int Cast5::GetChiperBlockSize()
    {
        return CAST_BLOCK;
    }
    
    int Cast5::GetKeyLength()
    {
        return CAST_KEY_LENGTH;
    }
    
    bool Cast5::EncryptBlock(const CharDataVector& input_data,
                              const CharDataVector& session_key,
                              CharDataVector& result_data)
    {
        CAST_KEY key;
        CAST_set_key(&key, GetKeyLength(), &session_key[0]);
        
        result_data.resize(input_data.size());
        
        CAST_ecb_encrypt(&input_data[0], &result_data[0], &key, CAST_ENCRYPT);
        
        return true;
    }
    
    bool Cast5::DecryptBlock(const CharDataVector& input_data,
                              const CharDataVector& session_key,
                              CharDataVector& result_data)
    {
        CAST_KEY key;
        CAST_set_key(&key, GetKeyLength(), &session_key[0]);
        
        result_data.resize(input_data.size());
        
        CAST_ecb_encrypt(&input_data[0], &result_data[0], &key, CAST_DECRYPT);

        return true;
    }

    
    bool Cast5::EncryptInCFBMode(const CharDataVector& input_data,
                        const CharDataVector& session_key,
                        CharDataVector& initial_vector,
                        CharDataVector& result_data)
    {
        CAST_KEY cast_key;
        CAST_set_key(&cast_key, GetKeyLength(), &session_key[0]);
        
        result_data.resize(input_data.size());
        CharDataVector ivec(initial_vector);
        
        int num = 0;
        CAST_cfb64_encrypt(&input_data[0], &result_data[0], input_data.size(), &cast_key, &ivec[0], &num, CAST_ENCRYPT);
        
        return true;
    }
    
    bool Cast5::DecryptInCFBMode(const CharDataVector& input_data,
                        const CharDataVector& session_key,
                        const CharDataVector& initial_vector,
                        CharDataVector& result_data)
    {
        CAST_KEY cast_key;
        CAST_set_key(&cast_key, GetKeyLength(), &session_key[0]);
        
        result_data.resize(input_data.size());
        CharDataVector ivec(initial_vector);

        int num = 0;
        CAST_cfb64_encrypt(&input_data[0], &result_data[0], input_data.size(), &cast_key, &ivec[0], &num, CAST_DECRYPT);
        
        return true;
    }

    int BlowFish::GetChiperBlockSize()
    {
        return BF_BLOCK;
    }
    
    int BlowFish::GetKeyLength()
    {
        return 16; // ???
    }
    
    bool BlowFish::EncryptBlock(const CharDataVector& input_data,
                              const CharDataVector& session_key,
                              CharDataVector& result_data)
    {
        BF_KEY key;
        BF_set_key(&key, GetKeyLength(), &session_key[0]);
        
        result_data.resize(input_data.size());
        
        BF_ecb_encrypt(&input_data[0], &result_data[0], &key, BF_ENCRYPT);
        
        return true;
    }
    
    bool BlowFish::DecryptBlock(const CharDataVector& input_data,
                              const CharDataVector& session_key,
                              CharDataVector& result_data)
    {
        BF_KEY key;
        BF_set_key(&key, GetKeyLength(), &session_key[0]);
        
        result_data.resize(input_data.size());
        
        BF_ecb_encrypt(&input_data[0], &result_data[0], &key, BF_DECRYPT);
        
        return true;
    }


    bool BlowFish::EncryptInCFBMode(const CharDataVector& input_data,
                           const CharDataVector& session_key,
                           CharDataVector& initial_vector,
                           CharDataVector& result_data)
    {
        BF_KEY key;
        BF_set_key(&key, GetKeyLength(), &session_key[0]);
        
        result_data.resize(input_data.size());
        
        int num = 0;
        BF_cfb64_encrypt(&input_data[0], &result_data[0], input_data.size(), &key, &initial_vector[0], &num, BF_ENCRYPT);
        
        return true;
    }
    
    bool BlowFish::DecryptInCFBMode(const CharDataVector& input_data,
                           const CharDataVector& session_key,
                           const CharDataVector& initial_vector,
                           CharDataVector& result_data)
    {
        BF_KEY key;
        BF_set_key(&key, GetKeyLength(), &session_key[0]);
        
        CharDataVector ivec(initial_vector);
        result_data.resize(input_data.size());
        
        int num = 0;
        BF_cfb64_encrypt(&input_data[0], &result_data[0], input_data.size(), &key, &ivec[0], &num, BF_DECRYPT);

        return true;
    }

    int AES128::GetChiperBlockSize()
    {
        return AES_BLOCK_SIZE;
    }
    
    int AES128::GetKeyLength()
    {
        return 16;
    }
    
    bool AES128::EncryptBlock(const CharDataVector& input_data,
                              const CharDataVector& session_key,
                              CharDataVector& result_data)
    {
        AES_KEY aes_key;
        AES_set_encrypt_key(&session_key[0], 128, &aes_key);
        
        AES_encrypt(&input_data[0], &result_data[0], &aes_key);
        
        return true;
    }
    
    bool AES128::DecryptBlock(const CharDataVector& input_data,
                              const CharDataVector& session_key,
                              CharDataVector& result_data)
    {
        AES_KEY aes_key;
        AES_set_decrypt_key(&session_key[0], 128, &aes_key);
        
        AES_decrypt(&input_data[0], &result_data[0], &aes_key);
        
        return true;
    }


    bool AES128::EncryptInCFBMode(const CharDataVector& input_data,
                         const CharDataVector& session_key,
                         CharDataVector& initial_vector,
                         CharDataVector& result_data)
    {
        result_data.resize(input_data.size());
        CharDataVector ivec(initial_vector);
        
        AES_KEY aes_key;
        AES_set_encrypt_key(&session_key[0], 128, &aes_key);
        
        int num = 0;
        AES_cfb128_encrypt(&input_data[0], &result_data[0], input_data.size(), &aes_key, &ivec[0], &num, AES_ENCRYPT);
        
        return true;
    }
    
    bool AES128::DecryptInCFBMode(const CharDataVector& input_data,
                         const CharDataVector& session_key,
                         const CharDataVector& initial_vector,
                         CharDataVector& result_data)
    {
        result_data.resize(input_data.size());
        CharDataVector ivec(initial_vector);
        
        AES_KEY aes_key;
        AES_set_encrypt_key(&session_key[0], 128, &aes_key);
        
        int num = 0;
        AES_cfb128_encrypt(&input_data[0], &result_data[0], input_data.size(), &aes_key, &ivec[0], &num, AES_DECRYPT);
        
        return true;
    }

    int AES192::GetChiperBlockSize()
    {
        return AES_BLOCK_SIZE;
    }
    
    int AES192::GetKeyLength()
    {
        return 24;
    }
    
    bool AES192::EncryptBlock(const CharDataVector& input_data,
                              const CharDataVector& session_key,
                              CharDataVector& result_data)
    {
        AES_KEY aes_key;
        AES_set_encrypt_key(&session_key[0], 192, &aes_key);
        
        AES_encrypt(&input_data[0], &result_data[0], &aes_key);
        
        return true;

    }
    
    bool AES192::DecryptBlock(const CharDataVector& input_data,
                              const CharDataVector& session_key,
                              CharDataVector& result_data)
    {
        AES_KEY aes_key;
        AES_set_decrypt_key(&session_key[0], 192, &aes_key);
        
        AES_decrypt(&input_data[0], &result_data[0], &aes_key);
        
        return true;
    }

    
    bool AES192::EncryptInCFBMode(const CharDataVector& input_data,
                         const CharDataVector& session_key,
                         CharDataVector& initial_vector,
                         CharDataVector& result_data)
    {
        result_data.resize(input_data.size());
        CharDataVector ivec(initial_vector);
        
        AES_KEY aes_key;
        AES_set_encrypt_key(&session_key[0], 192, &aes_key);
        
        int num = 0;
        AES_cfb128_encrypt(&input_data[0], &result_data[0], input_data.size(), &aes_key, &ivec[0], &num, AES_ENCRYPT);
        
        return true;

    }
    
    bool AES192::DecryptInCFBMode(const CharDataVector& input_data,
                         const CharDataVector& session_key,
                         const CharDataVector& initial_vector,
                         CharDataVector& result_data)

    {
        result_data.resize(input_data.size());
        CharDataVector ivec(initial_vector);
        
        AES_KEY aes_key;
        AES_set_encrypt_key(&session_key[0], 192, &aes_key);
        
        int num = 0;
        AES_cfb128_encrypt(&input_data[0], &result_data[0], input_data.size(), &aes_key, &ivec[0], &num, AES_DECRYPT);
        
        return true;
    }

    int AES256::GetChiperBlockSize()
    {
        return AES_BLOCK_SIZE;
    }
    
    int AES256::GetKeyLength()
    {
        return 32;
    }
    
    bool AES256::EncryptBlock(const CharDataVector& input_data,
                              const CharDataVector& session_key,
                              CharDataVector& result_data)
    {
        AES_KEY aes_key;
        AES_set_encrypt_key(&session_key[0], 256, &aes_key);
        
        AES_encrypt(&input_data[0], &result_data[0], &aes_key);
        
        return true;
    }
    
    bool AES256::DecryptBlock(const CharDataVector& input_data,
                              const CharDataVector& session_key,
                              CharDataVector& result_data)
    {
        AES_KEY aes_key;
        AES_set_decrypt_key(&session_key[0], 256, &aes_key);
        
        AES_decrypt(&input_data[0], &result_data[0], &aes_key);
        
        return true;
    }
    
    bool AES256::EncryptInCFBMode(const CharDataVector& input_data,
                         const CharDataVector& session_key,
                         CharDataVector& initial_vector,
                         CharDataVector& result_data)
    {
        result_data.resize(input_data.size());
        CharDataVector ivec(initial_vector);
        
        AES_KEY aes_key;
        AES_set_encrypt_key(&session_key[0], 256, &aes_key);
        
        int num = 0;
        AES_cfb128_encrypt(&input_data[0], &result_data[0], input_data.size(), &aes_key, &ivec[0], &num, AES_ENCRYPT);
        
        return true;
    }
    
    bool AES256::DecryptInCFBMode(const CharDataVector& input_data,
                         const CharDataVector& session_key,
                         const CharDataVector& initial_vector,
                         CharDataVector& result_data)

    {
        result_data.resize(input_data.size());
        CharDataVector ivec(initial_vector);
        
        AES_KEY aes_key;
        AES_set_encrypt_key(&session_key[0], 256, &aes_key);
        
        int num = 0;
        AES_cfb128_encrypt(&input_data[0], &result_data[0], input_data.size(), &aes_key, &ivec[0], &num, AES_DECRYPT);
        
        return true;
    }
    
    int TwoFish::GetChiperBlockSize()
    {
        return 16;
    }
    
    int TwoFish::GetKeyLength()
    {
        return 32;
    }
    
    bool TwoFish::EncryptBlock(const CharDataVector& input_data,
                              const CharDataVector& session_key,
                              CharDataVector& result_data)
    {
        return false;
    }
    
    bool TwoFish::DecryptBlock(const CharDataVector& input_data,
                              const CharDataVector& session_key,
                              CharDataVector& result_data)
    {
        return false;
    }

    
    bool TwoFish::EncryptInCFBMode(const CharDataVector& input_data,
                          const CharDataVector& session_key,
                          CharDataVector& initial_vector,
                          CharDataVector& result_data)
    {
        return false;
    }
    
    bool TwoFish::DecryptInCFBMode(const CharDataVector& input_data,
                          const CharDataVector& session_key,
                          const CharDataVector& initial_vector,
                          CharDataVector& result_data)

    {
        return false;
    }
    
    SymmetricKeyAlgorithmPtr GetSymmetricKeyAlgorithm(SymmetricKeyAlgorithms algo)
    {
        SymmetricKeyAlgorithmPtr symmetric_key_algo_impl(nullptr);
        
        switch (algo)
        {
            case SKA_PLAIN_TEXT:
                return nullptr;
            case SKA_IDEA:
                symmetric_key_algo_impl.reset(new Idea);
                break;
            case SKA_TRIPLE_DES:
                symmetric_key_algo_impl.reset(new TripleDes);
                break;
            case SKA_CAST5:
                symmetric_key_algo_impl.reset(new Cast5);
                break;
            case SKA_BLOWFISH:
                symmetric_key_algo_impl.reset(new BlowFish);
                break;
            case SKA_AES_128:
                symmetric_key_algo_impl.reset(new AES128);
                break;
            case SKA_AES_192:
                symmetric_key_algo_impl.reset(new AES192);
                break;
            case SKA_AES_256:
                symmetric_key_algo_impl.reset(new AES256);
                break;
            case SKA_TWOFISH:
                symmetric_key_algo_impl.reset(new TwoFish);
                break;

        }
        
        return symmetric_key_algo_impl;
    }


}
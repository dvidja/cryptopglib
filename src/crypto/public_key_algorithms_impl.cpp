//
//  PublicKeyAlgorithmsImpl.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 5.11.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "public_key_algorithms_impl.h"
extern "C" {
#include "openssl/bn.h"
#include "openssl/rsa.h"
#include "openssl/dsa.h"
#include "openssl/err.h"
#include "openssl/dh.h"
#include "openssl/rand.h"
}

namespace
{
    bool PKCSEncrypt()
    {
        return false;
    }
    
    bool PKCSDecrypt()
    {
        return false;
    }
}


namespace crypto
{
    int RSAAlgorithm::EncryptWithPrivateKey(SecretKeyPacketPtr secret_key, const CharDataVector& source_data, CharDataVector& result_data)
    {
        RSA* rsa_secret_key = RSA_new();

        CharDataVector mpi_n_data(secret_key->GetPublicKeyPatr()->GetMPI(0));
        auto n = BN_bin2bn(&mpi_n_data[0], static_cast<int>(mpi_n_data.size()), nullptr);
        
        CharDataVector mpi_e_data(secret_key->GetPublicKeyPatr()->GetMPI(1));
        auto e = BN_bin2bn(&mpi_e_data[0], static_cast<int>(mpi_e_data.size()), nullptr);
        
        CharDataVector mpi_d_data(secret_key->GetMPI(0));
        auto d = BN_bin2bn(&mpi_d_data[0], static_cast<int>(mpi_d_data.size()), nullptr);
        
        CharDataVector mpi_p_data(secret_key->GetMPI(1));
        auto p = BN_bin2bn(&mpi_p_data[0], static_cast<int>(mpi_p_data.size()), nullptr);
        
        CharDataVector mpi_q_data(secret_key->GetMPI(2));
        auto q = BN_bin2bn(&mpi_q_data[0], static_cast<int>(mpi_q_data.size()), nullptr);

        RSA_set0_key(rsa_secret_key, n, e, d);
        RSA_set0_factors(rsa_secret_key, p, q);
        
        result_data.resize(RSA_size(rsa_secret_key));
        int len = RSA_private_encrypt(static_cast<int>(source_data.size()), &source_data[0], &result_data[0], rsa_secret_key, RSA_PKCS1_PADDING);
        
        RSA_free(rsa_secret_key);

        return len;
    }
    
    int RSAAlgorithm::EncryptWithPublicKey(PublicKeyPacketPtr public_key, const CharDataVector& source_data, CharDataVector& result_data)
    {
        RSA* rsa_pub_key = RSA_new();
        
        CharDataVector mpi_n_data(public_key->GetMPI(0));
        auto n = BN_bin2bn(&mpi_n_data[0], static_cast<int>(mpi_n_data.size()), nullptr);
        
        CharDataVector mpi_e_data(public_key->GetMPI(1));
        auto e = BN_bin2bn(&mpi_e_data[0], static_cast<int>(mpi_e_data.size()), nullptr);

        RSA_set0_key(rsa_pub_key, n, e, nullptr);
        
        int rsa_len = RSA_size(rsa_pub_key);
        result_data.resize(rsa_len);
        
        int len = RSA_public_encrypt(static_cast<int>(source_data.size()), &source_data[0], &result_data[0], rsa_pub_key, RSA_PKCS1_PADDING);
        RSA_free(rsa_pub_key);
        
        return len;
    }
    
    int RSAAlgorithm::DecryptWithPrivateKey(SecretKeyPacketPtr secret_key, const CharDataVector& source_data, CharDataVector& result_data)
    {
        RSA* rsa_secret_key = RSA_new();
        
        CharDataVector mpi_n_data(secret_key->GetPublicKeyPatr()->GetMPI(0));
        auto n = BN_bin2bn(&mpi_n_data[0], static_cast<int>(mpi_n_data.size()), nullptr);
        
        CharDataVector mpi_e_data(secret_key->GetPublicKeyPatr()->GetMPI(1));
        auto e = BN_bin2bn(&mpi_e_data[0], static_cast<int>(mpi_e_data.size()), nullptr);
        
        CharDataVector mpi_d_data(secret_key->GetMPI(0));
        auto d = BN_bin2bn(&mpi_d_data[0], static_cast<int>(mpi_d_data.size()), nullptr);
        
        CharDataVector mpi_p_data(secret_key->GetMPI(1));
        auto p = BN_bin2bn(&mpi_p_data[0], static_cast<int>(mpi_p_data.size()), nullptr);
        
        CharDataVector mpi_q_data(secret_key->GetMPI(2));
        auto q = BN_bin2bn(&mpi_q_data[0], static_cast<int>(mpi_q_data.size()), nullptr);

        RSA_set0_key(rsa_secret_key, n, e, d);
        RSA_set0_factors(rsa_secret_key, p, q);

        int rsa_private_len = RSA_size(rsa_secret_key);
        result_data.resize(rsa_private_len);
        
        int len = RSA_private_decrypt(rsa_private_len, &source_data[0], &result_data[0], rsa_secret_key, RSA_PKCS1_PADDING);
        
        RSA_free(rsa_secret_key);
        
        result_data.erase(result_data.begin() + len, result_data.end());
        
        return len;
    }
    
    int RSAAlgorithm::DecryptWithPublicKey(PublicKeyPacketPtr public_key, const CharDataVector& source_data, CharDataVector& result_data)
    {
        RSA* rsa_pub_key = RSA_new();
        
        CharDataVector mpi_n_data(public_key->GetMPI(0));
        auto n = BN_bin2bn(&mpi_n_data[0], static_cast<int>(mpi_n_data.size()), nullptr);
        
        CharDataVector mpi_e_data(public_key->GetMPI(1));
        auto e = BN_bin2bn(&mpi_e_data[0], static_cast<int>(mpi_e_data.size()), nullptr);

        RSA_set0_key(rsa_pub_key, n, e, nullptr);

        int rsa_len = RSA_size(rsa_pub_key);
        result_data.resize(rsa_len);

        int len = RSA_public_decrypt(rsa_len, &source_data[0], &result_data[0], rsa_pub_key, RSA_PKCS1_PADDING);
        RSA_free(rsa_pub_key);

        if (len <= 0)
        {
            result_data.clear();
            return len;
        }
        
        result_data.erase(result_data.begin() + len, result_data.end());
   
        return len;
    }
    
    // sign data
    int DSSDHAlgorithm::EncryptWithPrivateKey(SecretKeyPacketPtr secret_key, const CharDataVector& source_data, CharDataVector& result_data)
    {
        //signature
        DSA* dsa_secret_key = DSA_new();
        
        CharDataVector mpi_x_data(secret_key->GetMPI(0));
        auto priv_key = BN_bin2bn(&mpi_x_data[0], static_cast<int>(mpi_x_data.size()), nullptr);
        
        PublicKeyPacketPtr public_key = secret_key->GetPublicKeyPatr();
        
        CharDataVector mpi_p_data(public_key->GetMPI(0));
        auto p = BN_bin2bn(&mpi_p_data[0], static_cast<int>(mpi_p_data.size()), nullptr);
        
        CharDataVector mpi_q_data(public_key->GetMPI(1));
        auto q = BN_bin2bn(&mpi_q_data[0], static_cast<int>(mpi_q_data.size()), nullptr);
        int num_bits = BN_num_bits(q);
        
        CharDataVector mpi_g_data(public_key->GetMPI(2));
        auto g = BN_bin2bn(&mpi_g_data[0], static_cast<int>(mpi_g_data.size()), nullptr);
        
        CharDataVector mpi_y_data(public_key->GetMPI(3));
        auto pub_key = BN_bin2bn(&mpi_y_data[0], static_cast<int>(mpi_y_data.size()), nullptr);

        DSA_set0_key(dsa_secret_key, pub_key, priv_key);

        unsigned int dsa_len = DSA_size(dsa_secret_key);
        result_data.resize(dsa_len);
        
        DSA_SIG* dsa_signature = DSA_do_sign(&source_data[0], static_cast<int>(source_data.size()),  dsa_secret_key);

        const BIGNUM *r, *s;
        DSA_SIG_get0(dsa_signature, &r, &s);
        CharDataVector mpi_r((BN_num_bytes(r)) * sizeof(char));
        BN_bn2bin(r, &mpi_r[0]);
        
        CharDataVector mpi_s((BN_num_bytes(s)) * sizeof(char));
        BN_bn2bin(s, &mpi_s[0]);
        
        CharDataVector encrypted_data;
        int num_bits_r = BN_num_bits(r);
        encrypted_data.push_back((num_bits_r >> 8) & 0xFF);
        encrypted_data.push_back(num_bits_r & 0xFF);
        encrypted_data.insert(encrypted_data.end(), mpi_r.begin(), mpi_r.end());
        
        int num_bits_s = BN_num_bits(s);
        encrypted_data.push_back((num_bits_s >> 8) & 0xFF);
        encrypted_data.push_back(num_bits_s & 0xFF);
        encrypted_data.insert(encrypted_data.end(), mpi_s.begin(), mpi_s.end());
        
        result_data.assign(encrypted_data.begin(), encrypted_data.end());
        
        
        DSA_free(dsa_secret_key);
        
        return 1;
    }
    
    int DSSDHAlgorithm::EncryptWithPublicKey(PublicKeyPacketPtr public_key, const CharDataVector& source_data, CharDataVector& result_data)
    {
        BIGNUM* p = BN_new();
        CharDataVector mpi_p_data(public_key->GetMPI(0));
        p = BN_bin2bn(&mpi_p_data[0], static_cast<int>(mpi_p_data.size()), nullptr);
        
        CharDataVector message = {0, 2};
        
        // encrypt PKCS rfc 4880 13.2
        {
            int k = BN_num_bytes(p);
            if (source_data.size() >= (k - 11))
            {
                return 0;
            }
            
            int ps_len = k - static_cast<int>(source_data.size()) - 3;
            CharDataVector PS(ps_len);
            if (!RAND_bytes(&PS[0], ps_len))
            {
                return 0;
            }
            
            for (int i = 0; i < PS.size(); ++i)
            {
                if (PS[i] == 0)
                {
                    do
                    {
                        int k = rand() % 256;
                        PS[i] = k;
                    }
                    while (k == 0);
                }
            }
            
            message.insert(message.end(), PS.begin(), PS.end());
            message.push_back(0);
            message.insert(message.end(), source_data.begin(), source_data.end());
        }


        BIGNUM* g = BN_new();
        CharDataVector mpi_g_data(public_key->GetMPI(1));
        g = BN_bin2bn(&mpi_g_data[0], static_cast<int>(mpi_g_data.size()), nullptr);

        BIGNUM* y = BN_new();
        CharDataVector mpi_y_data(public_key->GetMPI(2));
        y = BN_bin2bn(&mpi_y_data[0], static_cast<int>(mpi_y_data.size()), nullptr);
        
        BIGNUM* m = BN_new();
        m = BN_bin2bn(&message[0], static_cast<int>(message.size()), nullptr);

        BIGNUM* k = BN_new();
        BN_rand(k, BN_num_bits(p), 1, 1);
        
        
        BN_CTX* ctx;
        ctx = BN_CTX_new();
        
        BN_mod(k, k, p, ctx);
        
        BIGNUM* a = BN_new();
        BN_mod_exp(a, g, k, p, ctx);
        
        BIGNUM* s = BN_new();
        BN_mod_exp(s, y, k, p, ctx);
        
        BIGNUM* b = BN_new();
        BN_mod_mul(b, s, m, p, ctx);
        
        
        CharDataVector mpi_a((BN_num_bytes(a)) * sizeof(char));
        BN_bn2bin(a, &mpi_a[0]);
        
        CharDataVector mpi_b((BN_num_bytes(b)) * sizeof(char));
        BN_bn2bin(b, &mpi_b[0]);

        
        result_data.empty();
        int num_bits_a = BN_num_bits(a);
        result_data.push_back((num_bits_a >> 8) & 0xFF);
        result_data.push_back(num_bits_a & 0xFF);
        result_data.insert(result_data.end(), mpi_a.begin(), mpi_a.end());
        
        int num_bits_b = BN_num_bits(b);
        result_data.push_back((num_bits_b >> 8) & 0xFF);
        result_data.push_back(num_bits_b & 0xFF);
        result_data.insert(result_data.end(), mpi_b.begin(), mpi_b.end());

        
        BN_free(p);
        BN_free(g);
        BN_free(y);
        BN_free(m);
        BN_free(k);
        BN_free(a);
        BN_free(s);
        BN_free(b);
        BN_CTX_free(ctx);
        
        return result_data.size();
    }
    
    int DSSDHAlgorithm::DecryptWithPrivateKey(SecretKeyPacketPtr secret_key, const CharDataVector& source_data, CharDataVector& result_data)
    {
        CharDataVector mpi_x_data(secret_key->GetMPI(0));
        BIGNUM* x = BN_bin2bn(&mpi_x_data[0], static_cast<int>(mpi_x_data.size()), nullptr);
        
        CharDataVector mpi_p_data(secret_key->GetPublicKeyPatr()->GetMPI(0));
        BIGNUM* p = BN_bin2bn(&mpi_p_data[0], static_cast<int>(mpi_p_data.size()), nullptr);
        
        DataBuffer data_buffer(source_data);

        int l = data_buffer.GetNextTwoOctets();
        l = (l + 7) / 8;
        CharDataVector mpi_data_a = data_buffer.GetRange(l);
        BIGNUM* a = BN_bin2bn(&mpi_data_a[0], static_cast<int>(mpi_data_a.size()), nullptr);
        
        l = data_buffer.GetNextTwoOctets();
        l = (l + 7) / 8;
        CharDataVector mpi_data_b = data_buffer.GetRange(l);
        BIGNUM* b = BN_bin2bn(&mpi_data_b[0], static_cast<int>(mpi_data_b.size()), nullptr);
        
        BN_CTX* ctx;
        ctx = BN_CTX_new();

        BIGNUM* s = BN_new();
        BN_mod_exp(s, a, x, p, ctx);
        
        BIGNUM* m = BN_new();
        BN_mod_inverse(m, s, p, ctx);
        
        BIGNUM* result = BN_new();
        BN_mod_mul(result, b, m, p, ctx);
        
        result_data.resize(BN_num_bytes(result));
        
        BN_bn2bin(result, &result_data[0]);
        
        BN_free(x);
        BN_free(p);
        BN_free(a);
        BN_free(b);
        BN_free(s);
        BN_free(m);
        BN_free(result);
        BN_CTX_free(ctx);
        
        // decrypt PKCS rfc 4880 13.2
        if (result_data.size() > 10)
        {
            if (result_data[0] != 2)
            {
                result_data.empty();
                return 0;
            }
            
            auto ps_end = std::find(result_data.begin(), result_data.end(), 0);
            if (ps_end != result_data.end())
            {
                result_data.erase(result_data.begin(), ps_end + 1);
                
                return static_cast<int>(result_data.size());
            }
        }
        
        return 0;
    }
    
    // check signature
    int DSSDHAlgorithm::DecryptWithPublicKey(PublicKeyPacketPtr public_key, const CharDataVector& source_data, CharDataVector& result_data)
    {
        DSA* dsa_public_key = DSA_new();
        
        CharDataVector mpi_p_data(public_key->GetMPI(0));
        auto p = BN_bin2bn(&mpi_p_data[0], static_cast<int>(mpi_p_data.size()), nullptr);
        
        CharDataVector mpi_q_data(public_key->GetMPI(1));
        auto q = BN_bin2bn(&mpi_q_data[0], static_cast<int>(mpi_q_data.size()), nullptr);
        
        CharDataVector mpi_g_data(public_key->GetMPI(2));
        auto g = BN_bin2bn(&mpi_g_data[0], static_cast<int>(mpi_g_data.size()), nullptr);
        
        CharDataVector mpi_y_data(public_key->GetMPI(3));
        auto pub_key = BN_bin2bn(&mpi_y_data[0], static_cast<int>(mpi_y_data.size()), nullptr);
        
        DSA_SIG* dsa_signature = DSA_SIG_new();
        
        DataBuffer data_buffer(result_data);
        
        int l = data_buffer.GetNextTwoOctets();
        l = (l + 7) / 8;
        
        CharDataVector mpi_data_r = data_buffer.GetRange(l);
        auto r = BN_bin2bn(&mpi_data_r[0], static_cast<int>(mpi_data_r.size()), nullptr);
        
        l = data_buffer.GetNextTwoOctets();
        l = (l + 7) / 8;
        
        CharDataVector mpi_data_s = data_buffer.GetRange(l);
        auto s = BN_bin2bn(&mpi_data_s[0], static_cast<int>(mpi_data_s.size()), nullptr);

        DSA_set0_pqg(dsa_public_key, p, q, g);
        DSA_SIG_set0(dsa_signature, r, s);
        int res = DSA_do_verify(&source_data[0], static_cast<int>(source_data.size()), dsa_signature, dsa_public_key);
        
        DSA_SIG_free(dsa_signature);
        DSA_free(dsa_public_key);
        
        return res;
    }
    
    PublicKeyAlgorithmPtr GetPublicKeyAlgorithm(PublicKeyAlgorithms algo)
    {
        PublicKeyAlgorithmPtr public_key_algo_impl(nullptr);
        
        switch (algo)
        {
            case PKA_RSA:
            case PKA_RSA_ENCRYPT_ONLY:
            case PKA_RSA_SIGN_ONLY:
                public_key_algo_impl = std::make_unique<RSAAlgorithm>();
                break;
                
            case PKA_ELGAMAL:
                public_key_algo_impl = std::make_unique<DSSDHAlgorithm>();
                break;
                
            case PKA_DSA:
                public_key_algo_impl = std::make_unique<DSSDHAlgorithm>();
                break;
                
            default:
                break;
        }
        
        return public_key_algo_impl;
    }
}
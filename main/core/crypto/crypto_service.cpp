#include "core/crypto/crypto_service.hpp"
#include "mbedtls/chachapoly.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include <cstring>

namespace cryptalk::crypto {
    int CryptoService::encrypt_text(
        const std::array<uint8_t, 32>& key,
        const uint8_t* plaintext,
        size_t plaintext_len,
        const uint8_t* aad,
        size_t aad_len,
        std::vector<uint8_t>& ciphertext_out,
        std::array<uint8_t, 12>& nonce_out,
        std::array<uint8_t, 16>& tag_out)
    {
        mbedtls_chachapoly_context ctx;
        mbedtls_chachapoly_init(&ctx);

        int rc = mbedtls_chachapoly_setkey(&ctx, key.data());

        if (rc != 0) {
            mbedtls_chachapoly_free(&ctx);
            return rc;
        }

        int nonce_result = generate_nonce(nonce_out);

        if (nonce_result != 0) {
            mbedtls_chachapoly_free(&ctx);

            return nonce_result;
        }

        rc = mbedtls_chachapoly_encrypt_and_tag(
            &ctx, 
            plaintext_len, 
            nonce_out.data(), 
            aad, 
            aad_len, 
            plaintext,
            ciphertext_out.data(),
            tag_out.data());

        mbedtls_chachapoly_free(&ctx);

        return rc;
    }

    int CryptoService::generate_nonce(std::array<uint8_t, 12>& out_nonce) {
        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context ctr_drbg;

        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);

        const char* pers = "cryptalk-nonce";

        int rc = mbedtls_ctr_drbg_seed(
            &ctr_drbg,
            mbedtls_entropy_func,
            &entropy,
            reinterpret_cast<const unsigned char*>(pers),
            std::strlen(pers)
        );

        if (rc != 0) {
            mbedtls_ctr_drbg_free(&ctr_drbg);
            mbedtls_entropy_free(&entropy);

            return rc;
        }

        rc = mbedtls_ctr_drbg_random(
            &ctr_drbg,
            out_nonce.data(),
            out_nonce.size()
        );

        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);

        return rc;
    }

    int CryptoService::decrypt_text(
        const uint8_t key[32],
        const uint8_t* ciphertext,
        size_t ciphertext_len,
        const uint8_t nonce[12],
        const uint8_t* aad,
        size_t aad_len,
        const uint8_t tag[16],
        std::vector<uint8_t>& plaintext_out)
    {
        mbedtls_chachapoly_context ctx;
        mbedtls_chachapoly_init(&ctx);

        int rc = mbedtls_chachapoly_setkey(&ctx, key);

        if (rc != 0) {
            mbedtls_chachapoly_free(&ctx);
            return rc;
        }

        rc = mbedtls_chachapoly_auth_decrypt(
            &ctx,
            ciphertext_len,
            nonce,
            aad,
            aad_len,
            tag,
            ciphertext,
            plaintext_out.data()
        );

        mbedtls_chachapoly_free(&ctx);

        return rc;
    }

    int CryptoService::generate_key() 
    {
        return 0;
    }

    int CryptoService::generate_unique_id(uint64_t& out_id)
    {
        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context ctr_drbg;
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);

        const char* pers = "cryptalk-msg-id";

        int rc = mbedtls_ctr_drbg_seed(
            &ctr_drbg, 
            mbedtls_entropy_func, 
            &entropy, 
            reinterpret_cast<const unsigned char*>(pers), 
            std::strlen(pers));

        if (rc != 0) {
            mbedtls_ctr_drbg_free(&ctr_drbg);
            mbedtls_entropy_free(&entropy);

            return rc;
        }

        rc = mbedtls_ctr_drbg_random(
            &ctr_drbg, 
            reinterpret_cast<unsigned char*>(&out_id), 
            sizeof(out_id));

        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);

        return rc;
    }
}
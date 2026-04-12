#pragma once

#include <array>
#include <cstdint>
#include <vector>

namespace cryptalk::crypto {
class CryptoService {
public:
    int encrypt_text(const std::array<uint8_t, 32>& key,
                     const uint8_t* plaintext,
                     size_t plaintext_len,
                     const uint8_t* aad,
                     size_t aad_len,
                     std::vector<uint8_t>& ciphertext_out,
                     std::array<uint8_t, 12>& nonce_out,
                     std::array<uint8_t, 16>& tag_out);

    int decrypt_text(const uint8_t key[32],
                     const uint8_t* ciphertext,
                     size_t ciphertext_len,
                     const uint8_t nonce[12],
                     const uint8_t* aad,
                     size_t aad_len,
                     const uint8_t tag[16],
                     std::vector<uint8_t>& plaintext_out);

    int generate_key();
    int generate_unique_id(uint64_t& out_id);

private:
    int generate_nonce(std::array<uint8_t, 12>& out_nonce);
};
}
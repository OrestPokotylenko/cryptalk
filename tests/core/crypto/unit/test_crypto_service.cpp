// tests/core/crypto/unit/test_crypto_service.cpp
#include <cassert>
#include <iostream>
#include <vector>
#include <array>
#include <cstdint>
#include <cstring>

#include "core/messaging/message_aad.hpp"
#include "core/crypto/crypto_service.hpp"

using cryptalk::crypto::CryptoService;

static const std::array<uint8_t, 32> TEST_KEY = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F
};

static std::vector<uint8_t> make_test_aad() {
    std::array<uint8_t, 16> sender_id = {
        0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C,
        0x0D, 0x0E, 0x0F, 0x10
    };

    std::array<uint8_t, 16> receiver_id = {
        0xA1, 0xA2, 0xA3, 0xA4,
        0xA5, 0xA6, 0xA7, 0xA8,
        0xA9, 0xAA, 0xAB, 0xAC,
        0xAD, 0xAE, 0xAF, 0xB0
    };

    return cryptalk::messaging::build_message_aad(
        1,
        2,
        3,
        0x11223344,
        sender_id,
        receiver_id
    );
}

static void test_generate_unique_id() {
    CryptoService service;

    uint64_t id1 = 0;
    uint64_t id2 = 0;

    int rc1 = service.generate_unique_id(id1);
    int rc2 = service.generate_unique_id(id2);

    assert(rc1 == 0);
    assert(rc2 == 0);
    assert(id1 != 0);
    assert(id2 != 0);

    std::cout << "[PASS] generate_unique_id\n";
}

static void test_encrypt_decrypt_roundtrip() {
    CryptoService service;

    const uint8_t plaintext[] = "hello cryptalk";
    const size_t plaintext_len = sizeof(plaintext) - 1;

    std::vector<uint8_t> aad = make_test_aad();

    std::vector<uint8_t> ciphertext_out(plaintext_len);
    std::array<uint8_t, 12> nonce_out{};
    std::array<uint8_t, 16> tag_out{};

    int enc_rc = service.encrypt_text(
        TEST_KEY,
        plaintext,
        plaintext_len,
        aad.data(),
        aad.size(),
        ciphertext_out,
        nonce_out,
        tag_out
    );

    assert(enc_rc == 0);
    assert(ciphertext_out.size() == plaintext_len);
    assert(std::memcmp(ciphertext_out.data(), plaintext, plaintext_len) != 0);

    std::vector<uint8_t> decrypted_out(plaintext_len);

    int dec_rc = service.decrypt_text(
        TEST_KEY.data(),
        ciphertext_out.data(),
        ciphertext_out.size(),
        nonce_out.data(),
        aad.data(),
        aad.size(),
        tag_out.data(),
        decrypted_out
    );

    assert(dec_rc == 0);
    assert(std::memcmp(decrypted_out.data(), plaintext, plaintext_len) == 0);

    std::cout << "[PASS] encrypt/decrypt roundtrip\n";
}

static void test_decrypt_fails_with_wrong_tag() {
    CryptoService service;

    const uint8_t plaintext[] = "hello cryptalk";
    const size_t plaintext_len = sizeof(plaintext) - 1;

    std::vector<uint8_t> aad = make_test_aad();

    std::vector<uint8_t> ciphertext_out(plaintext_len);
    std::array<uint8_t, 12> nonce_out{};
    std::array<uint8_t, 16> tag_out{};

    int enc_rc = service.encrypt_text(
        TEST_KEY,
        plaintext,
        plaintext_len,
        aad.data(),
        aad.size(),
        ciphertext_out,
        nonce_out,
        tag_out
    );

    assert(enc_rc == 0);

    tag_out[0] ^= 0xFF;

    std::vector<uint8_t> decrypted_out(plaintext_len);

    int dec_rc = service.decrypt_text(
        TEST_KEY.data(),
        ciphertext_out.data(),
        ciphertext_out.size(),
        nonce_out.data(),
        aad.data(),
        aad.size(),
        tag_out.data(),
        decrypted_out
    );

    assert(dec_rc != 0);

    std::cout << "[PASS] wrong tag rejected\n";
}

static void test_decrypt_fails_with_wrong_aad() {
    CryptoService service;

    const uint8_t plaintext[] = "hello cryptalk";
    const size_t plaintext_len = sizeof(plaintext) - 1;

    std::vector<uint8_t> aad = make_test_aad();

    std::vector<uint8_t> ciphertext_out(plaintext_len);
    std::array<uint8_t, 12> nonce_out{};
    std::array<uint8_t, 16> tag_out{};

    int enc_rc = service.encrypt_text(
        TEST_KEY,
        plaintext,
        plaintext_len,
        aad.data(),
        aad.size(),
        ciphertext_out,
        nonce_out,
        tag_out
    );

    assert(enc_rc == 0);

    aad[0] ^= 0xFF;

    std::vector<uint8_t> decrypted_out(plaintext_len);

    int dec_rc = service.decrypt_text(
        TEST_KEY.data(),
        ciphertext_out.data(),
        ciphertext_out.size(),
        nonce_out.data(),
        aad.data(),
        aad.size(),
        tag_out.data(),
        decrypted_out
    );

    assert(dec_rc != 0);

    std::cout << "[PASS] wrong AAD rejected\n";
}

int main() {
    test_generate_unique_id();
    test_encrypt_decrypt_roundtrip();
    test_decrypt_fails_with_wrong_tag();
    test_decrypt_fails_with_wrong_aad();

    std::cout << "All crypto unit tests passed\n";
    return 0;
}
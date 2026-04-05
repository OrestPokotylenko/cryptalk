#include <cassert>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <array>
#include <vector>
#include <string>

#include "core/messaging/message_service.hpp"
#include "core/crypto/crypto_service.hpp"

using cryptalk::messaging::Message;
using cryptalk::messaging::MessageService;
using cryptalk::crypto::CryptoService;

static const std::array<uint8_t, 32> MOCK_KEY = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F
};

static const std::array<uint8_t, 16> RECEIVER_ID = {
    0x11, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x77, 0x88,
    0x99, 0xAA, 0xBB, 0xCC,
    0xDD, 0xEE, 0xF0, 0x01
};

static void print_bytes(const char* label, const uint8_t* data, size_t len) {
    std::cout << label << " (" << len << " bytes): ";
    for (size_t i = 0; i < len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]) << ' ';
    }
    std::cout << std::dec << '\n';
}

static void append_u32_be(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back((value >> 24) & 0xFF);
    out.push_back((value >> 16) & 0xFF);
    out.push_back((value >> 8) & 0xFF);
    out.push_back(value & 0xFF);
}

static std::vector<uint8_t> build_aad_from_message(const Message& msg) {
    std::vector<uint8_t> aad;
    aad.reserve(1 + 1 + 1 + 4 + 16 + 16);

    aad.push_back(msg.header.version);
    aad.push_back(msg.header.type);
    aad.push_back(msg.header.flags);
    append_u32_be(aad, msg.header.message_id);
    aad.insert(aad.end(), msg.header.sender_id.begin(), msg.header.sender_id.end());
    aad.insert(aad.end(), msg.header.receiver_id.begin(), msg.header.receiver_id.end());

    return aad;
}

static int decrypt_message(
    CryptoService& crypto_service,
    const Message& msg,
    const uint8_t* aad,
    size_t aad_len,
    std::vector<uint8_t>& decrypted_out
) {
    decrypted_out.assign(msg.ciphertext.size(), 0);

    return crypto_service.decrypt_text(
        MOCK_KEY.data(),
        msg.ciphertext.data(),
        msg.ciphertext.size(),
        msg.nonce.data(),
        aad,
        aad_len,
        msg.tag.data(),
        decrypted_out
    );
}

static Message generate_test_message(const uint8_t* plaintext, size_t plaintext_len) {
    MessageService message_service;
    Message msg{};

    std::array<uint8_t, 16> receiver_id = RECEIVER_ID;

    int rc = message_service.generate_message(
        plaintext,
        plaintext_len,
        2,
        1,
        receiver_id,
        msg
    );

    assert(rc == 0);
    return msg;
}

static void print_message_summary(const Message& msg) {
    std::cout << "Header:\n";
    std::cout << "  version      = " << static_cast<int>(msg.header.version) << "\n";
    std::cout << "  type         = " << static_cast<int>(msg.header.type) << "\n";
    std::cout << "  flags        = " << static_cast<int>(msg.header.flags) << "\n";
    std::cout << "  message_id   = " << msg.header.message_id << "\n";
    std::cout << "  cipher_len   = " << msg.header.ciphertext_len << "\n";

    print_bytes("Sender ID", msg.header.sender_id.data(), msg.header.sender_id.size());
    print_bytes("Receiver ID", msg.header.receiver_id.data(), msg.header.receiver_id.size());
    print_bytes("Ciphertext", msg.ciphertext.data(), msg.ciphertext.size());
    print_bytes("Nonce", msg.nonce.data(), msg.nonce.size());
    print_bytes("Tag", msg.tag.data(), msg.tag.size());
}

static void test_create_and_decrypt_message_roundtrip() {
    std::cout << "\n=== Roundtrip test ===\n";

    CryptoService crypto_service;
    const uint8_t plaintext[] = "hello cryptalk";
    const size_t plaintext_len = sizeof(plaintext) - 1;

    Message msg = generate_test_message(plaintext, plaintext_len);

    std::cout << "Plaintext: " << reinterpret_cast<const char*>(plaintext) << "\n";
    print_message_summary(msg);

    assert(msg.ciphertext.size() == plaintext_len);
    assert(std::memcmp(msg.ciphertext.data(), plaintext, msg.ciphertext.size()) != 0);

    std::vector<uint8_t> aad = build_aad_from_message(msg);

    std::vector<uint8_t> decrypted_out;
    int rc = decrypt_message(
        crypto_service,
        msg,
        aad.data(),
        aad.size(),
        decrypted_out
    );

    std::cout << "decrypt_text rc = " << rc << "\n";
    assert(rc == 0);

    std::cout << "Decrypted text: "
              << std::string(decrypted_out.begin(), decrypted_out.end()) << "\n";

    assert(decrypted_out.size() == plaintext_len);
    assert(std::memcmp(decrypted_out.data(), plaintext, decrypted_out.size()) == 0);

    std::cout << "[PASS] Roundtrip\n";
}

static void test_tampered_ciphertext_should_fail() {
    std::cout << "\n=== Tampered ciphertext test ===\n";

    CryptoService crypto_service;
    const uint8_t plaintext[] = "hello cryptalk";
    const size_t plaintext_len = sizeof(plaintext) - 1;

    Message msg = generate_test_message(plaintext, plaintext_len);
    std::vector<uint8_t> aad = build_aad_from_message(msg);

    msg.ciphertext[0] ^= 0xFF;
    print_bytes("Tampered Ciphertext", msg.ciphertext.data(), msg.ciphertext.size());

    std::vector<uint8_t> decrypted_out;
    int rc = decrypt_message(
        crypto_service,
        msg,
        aad.data(),
        aad.size(),
        decrypted_out
    );

    std::cout << "decrypt_text rc = " << rc << "\n";
    assert(rc != 0);

    std::cout << "[PASS] Tampered ciphertext rejected\n";
}

static void test_wrong_tag_should_fail() {
    std::cout << "\n=== Wrong tag test ===\n";

    CryptoService crypto_service;
    const uint8_t plaintext[] = "hello cryptalk";
    const size_t plaintext_len = sizeof(plaintext) - 1;

    Message msg = generate_test_message(plaintext, plaintext_len);
    std::vector<uint8_t> aad = build_aad_from_message(msg);

    msg.tag[0] ^= 0xFF;
    print_bytes("Tampered Tag", msg.tag.data(), msg.tag.size());

    std::vector<uint8_t> decrypted_out;
    int rc = decrypt_message(
        crypto_service,
        msg,
        aad.data(),
        aad.size(),
        decrypted_out
    );

    std::cout << "decrypt_text rc = " << rc << "\n";
    assert(rc != 0);

    std::cout << "[PASS] Wrong tag rejected\n";
}

static void test_wrong_aad_should_fail() {
    std::cout << "\n=== Wrong AAD test ===\n";

    CryptoService crypto_service;
    const uint8_t plaintext[] = "hello cryptalk";
    const size_t plaintext_len = sizeof(plaintext) - 1;

    Message msg = generate_test_message(plaintext, plaintext_len);
    std::vector<uint8_t> aad = build_aad_from_message(msg);

    aad[0] ^= 0xFF; // corrupt version byte in AAD

    std::vector<uint8_t> decrypted_out;
    int rc = decrypt_message(
        crypto_service,
        msg,
        aad.data(),
        aad.size(),
        decrypted_out
    );

    std::cout << "decrypt_text rc = " << rc << "\n";
    assert(rc != 0);

    std::cout << "[PASS] Wrong AAD rejected\n";
}

int main() {
    test_create_and_decrypt_message_roundtrip();
    test_tampered_ciphertext_should_fail();
    test_wrong_tag_should_fail();
    test_wrong_aad_should_fail();

    std::cout << "\nAll integration tests passed\n";
    return 0;
}
#include "core/messaging/message/message_factory.hpp"
#include "core/messaging/message/message_aad.hpp"

#include "core/crypto/crypto_service.hpp"
#include "persistence/repositories/device_config_repository.hpp"
#include "persistence/repositories/peer_key_repository.hpp"

namespace cryptalk::messaging {
int MessageFactory::generate_message(const uint8_t* plaintext,
                                     size_t plaintext_len,
                                     uint8_t type,
                                     uint8_t flag,
                                     std::array<uint8_t, 16>& receiver_id,
                                     Message& out_message) {
    if (plaintext == nullptr) {
        return -1;
    }

    if (plaintext_len == 0) {
        return -2;
    }

    cryptalk::crypto::CryptoService crypto_service;
    cryptalk::persistence::PeerKeyRepository shared_key_repository;
    cryptalk::persistence::DeviceConfigRepository device_config_repository;

    std::array<uint8_t, 32> key;
    int key_result = shared_key_repository.get_key_by_id(receiver_id, key);

    if (key_result != 0) {
        return -5;
    }

    std::array<uint8_t, 16> device_id;
    int config_result = device_config_repository.get_device_id(device_id);

    if (config_result != 0) {
        return -1;
    }

    uint64_t message_id = 0;
    int id_result = crypto_service.generate_unique_id(message_id);

    if (id_result != 0) {
        return -1;
    }

    int version = 1;
    std::vector<uint8_t> aad =
        build_message_aad(version, type, flag, message_id, device_id, receiver_id);

    std::array<uint8_t, 16> tag_out = {};
    std::array<uint8_t, 12> nonce_out = {};
    std::vector<uint8_t> ciphertext_out(plaintext_len);

    int rc = crypto_service.encrypt_text(key,
                                         plaintext,
                                         plaintext_len,
                                         aad.data(),
                                         aad.size(),
                                         ciphertext_out,
                                         nonce_out,
                                         tag_out);

    if (rc != 0) {
        return rc;
    }

    MessageHeader message_header{};
    message_header.version = 1;
    message_header.type = type;
    message_header.flags = flag;
    message_header.reserved = 0;
    message_header.message_id = message_id;
    message_header.sender_id = device_id;
    message_header.receiver_id = receiver_id;
    message_header.ciphertext_len = ciphertext_out.size();

    out_message.header = message_header;
    out_message.ciphertext = ciphertext_out;
    out_message.nonce = nonce_out;
    out_message.tag = tag_out;

    return 0;
}
}
#pragma once

#include <array>
#include <cstdint>

namespace cryptalk::messaging {
struct MessageHeader {
    uint8_t version;
    uint8_t type;
    uint8_t flags;
    uint8_t reserved;

    uint64_t message_id;
    std::array<uint8_t, 16> sender_id;
    std::array<uint8_t, 16> receiver_id;
    uint32_t ciphertext_len;
};
}
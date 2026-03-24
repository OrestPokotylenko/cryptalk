#pragma once

#include <vector>
#include <array>
#include "message_header.hpp"

namespace cryptalk::messaging {
    struct Message
    {
        static constexpr size_t NonceSize = 12;
        static constexpr size_t TagSize = 16;

        MessageHeader header;
        std::vector<uint8_t> ciphertext;
        std::array<uint8_t, NonceSize> nonce{};
        std::array<uint8_t, TagSize> tag{};
    };
}
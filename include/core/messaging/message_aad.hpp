#pragma once

#include <array>
#include <cstdint>
#include <vector>

namespace cryptalk::messaging {
    std::vector<uint8_t> build_message_aad(
        uint8_t version,
        uint8_t type,
        uint8_t flag,
        uint32_t message_id,
        const std::array<uint8_t, 16>& sender_id,
        const std::array<uint8_t, 16>& receiver_id
    );
}
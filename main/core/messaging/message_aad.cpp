#include "core/messaging/message_aad.hpp"

namespace cryptalk::messaging {
    static void append_u32_be(std::vector<uint8_t>& out, uint32_t value) {
        out.push_back((value >> 24) & 0xFF);
        out.push_back((value >> 16) & 0xFF);
        out.push_back((value >> 8) & 0xFF);
        out.push_back(value & 0xFF);
    }

    std::vector<uint8_t> build_message_aad(
        uint8_t version,
        uint8_t type,
        uint8_t flag,
        uint32_t message_id,
        const std::array<uint8_t, 16>& sender_id,
        const std::array<uint8_t, 16>& receiver_id
    ) {
        std::vector<uint8_t> aad;
        aad.reserve(1 + 1 + 1 + 4 + 16 + 16);

        aad.push_back(version);
        aad.push_back(type);
        aad.push_back(flag);

        append_u32_be(aad, message_id);

        aad.insert(aad.end(), sender_id.begin(), sender_id.end());
        aad.insert(aad.end(), receiver_id.begin(), receiver_id.end());

        return aad;
    }
}
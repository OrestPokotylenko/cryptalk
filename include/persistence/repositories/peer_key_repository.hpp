#pragma once

#include <cstdint>
#include <array>

namespace cryptalk::persistence {
    class PeerKeyRepository {
        public:
            int get_key_by_id(std::array<uint8_t, 16> &contact_id, std::array<uint8_t, 32> &out_key);
    };
}
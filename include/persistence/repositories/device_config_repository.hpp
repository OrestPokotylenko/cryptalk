#pragma once

#include <cstdint>
#include <array>

namespace cryptalk::persistence {
    class DeviceConfigRepository {
        public:
            int get_device_id(std::array<uint8_t, 16> &out_id);
            int get_message_id();
    };
}
#include "persistence/repositories/device_config_repository.hpp"

namespace cryptalk::persistence {
    int DeviceConfigRepository::get_device_id(std::array<uint8_t, 16> &out_id) {
        out_id = { 
            0x9A, 0xF3, 0x47, 0x2C, 
            0xB1, 0x6D, 0x88, 0xE5,
            0x3F, 0x0A, 0xC9, 0x71,
            0x54, 0xDE, 0x2B, 0x90
        };
        
        return 0;
    }
}
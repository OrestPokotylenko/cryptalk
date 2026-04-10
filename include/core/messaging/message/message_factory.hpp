#pragma once

#include "message.hpp"

namespace cryptalk::messaging {
    class MessageFactory {
        public:
            int generate_message(
                const uint8_t* plaintext, 
                size_t plaintext_len, 
                uint8_t type, 
                uint8_t flag,
                std::array<uint8_t, 16> &receiver_id, 
                Message& out_message
            );
    };
}
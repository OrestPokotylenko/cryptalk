#pragma once

#include <cstdint>

namespace cryptalk::messaging {
    struct MessageHeader {
        uint8_t version;
        uint8_t type;
        uint8_t flags;
        uint8_t reserved;

        uint32_t message_id;
        uint32_t sender_id;
        uint32_t receiver_id;
        uint32_t cyphertext_len;
    };
}
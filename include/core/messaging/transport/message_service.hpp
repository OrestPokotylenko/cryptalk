#pragma once

#include "../message/message.hpp"

namespace cryptalk::messaging {
class MessageService {
public:
    int send_message(const uint8_t* plaintext, std::array<uint8_t, 16>& receiver_id);

    int receive_message(Message& message);
};
}
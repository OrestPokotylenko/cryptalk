#pragma once

namespace cryptalk::messaging {
    class MessageService {
        public:
            int send_message();
            int receive_message();
    };
}
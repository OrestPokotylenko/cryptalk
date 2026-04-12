// tests/core/messaging/unit/test_message_service.cpp
#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <vector>

#include "core/messaging/message/message_aad.hpp"

static void test_build_message_aad_layout() {
    std::array<uint8_t, 16> sender_id = {0x01,
                                         0x02,
                                         0x03,
                                         0x04,
                                         0x05,
                                         0x06,
                                         0x07,
                                         0x08,
                                         0x09,
                                         0x0A,
                                         0x0B,
                                         0x0C,
                                         0x0D,
                                         0x0E,
                                         0x0F,
                                         0x10};

    std::array<uint8_t, 16> receiver_id = {0xA1,
                                           0xA2,
                                           0xA3,
                                           0xA4,
                                           0xA5,
                                           0xA6,
                                           0xA7,
                                           0xA8,
                                           0xA9,
                                           0xAA,
                                           0xAB,
                                           0xAC,
                                           0xAD,
                                           0xAE,
                                           0xAF,
                                           0xB0};

    std::vector<uint8_t> aad =
        cryptalk::messaging::build_message_aad(1, 2, 3, 0x11223344, sender_id, receiver_id);

    assert(aad.size() == 39);

    // version, type, flags
    assert(aad[0] == 0x01);
    assert(aad[1] == 0x02);
    assert(aad[2] == 0x03);

    // message_id in big-endian
    assert(aad[3] == 0x11);
    assert(aad[4] == 0x22);
    assert(aad[5] == 0x33);
    assert(aad[6] == 0x44);

    // sender_id starts at offset 7
    for (size_t i = 0; i < 16; i++) {
        assert(aad[7 + i] == sender_id[i]);
    }

    // receiver_id starts at offset 23
    for (size_t i = 0; i < 16; i++) {
        assert(aad[23 + i] == receiver_id[i]);
    }

    std::cout << "[PASS] build_message_aad layout\n";
}

int main() {
    test_build_message_aad_layout();
    std::cout << "All messaging unit tests passed\n";
    return 0;
}
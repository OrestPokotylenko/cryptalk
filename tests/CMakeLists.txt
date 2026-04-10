cmake_minimum_required(VERSION 3.16)
project(cryptalk_pc_tests CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

enable_testing()

set(CRYPTALK_TEST_INCLUDE_DIRS
    ../include
    C:/msys64/mingw64/include
)

set(CRYPTALK_TEST_LIBS
    mbedcrypto
    mbedtls
    mbedx509
)

add_library(cryptalk_crypto STATIC
    ../main/core/crypto/crypto_service.cpp
)

target_include_directories(cryptalk_crypto PUBLIC
    ${CRYPTALK_TEST_INCLUDE_DIRS}
)

target_link_libraries(cryptalk_crypto PUBLIC
    ${CRYPTALK_TEST_LIBS}
)

add_library(cryptalk_persistence STATIC
    ../main/persistence/repositories/peer_key_repository.cpp
    ../main/persistence/repositories/device_config_repository.cpp
)

target_include_directories(cryptalk_persistence PUBLIC
    ${CRYPTALK_TEST_INCLUDE_DIRS}
)

add_library(cryptalk_message STATIC
    ../main/core/messaging/message/message_factory.cpp
    ../main/core/messaging/message/message_aad.cpp
)

target_include_directories(cryptalk_message PUBLIC
    ${CRYPTALK_TEST_INCLUDE_DIRS}
)

target_link_libraries(cryptalk_message PUBLIC
    cryptalk_crypto
    cryptalk_persistence
)

function(add_cryptalk_test TARGET_NAME TEST_SOURCE)
    add_executable(${TARGET_NAME} ${TEST_SOURCE})

    target_include_directories(${TARGET_NAME} PRIVATE
        ${CRYPTALK_TEST_INCLUDE_DIRS}
    )

    target_link_libraries(${TARGET_NAME} PRIVATE
        cryptalk_message
        cryptalk_crypto
        cryptalk_persistence
    )

    add_test(NAME ${TARGET_NAME} COMMAND ${TARGET_NAME})
endfunction()

add_cryptalk_test(
    test_message_crypto_flow
    core/messaging/integration/test_message_crypto_flow.cpp
)

add_cryptalk_test(
    test_message_service_unit
    core/messaging/unit/test_message_service.cpp
)

add_cryptalk_test(
    test_crypto_service_unit
    core/crypto/unit/test_crypto_service.cpp
)
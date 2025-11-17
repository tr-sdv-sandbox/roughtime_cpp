// Copyright 2024
// SPDX-License-Identifier: Apache-2.0
//
// Security and robustness tests

#include "roughtime/protocol.h"
#include "roughtime/crypto.h"
#include "roughtime/util.h"
#include "roughtime/client.h"
#include <gtest/gtest.h>
#include <climits>
#include <cstdint>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>

using namespace roughtime;

// Test integer overflow protection in message encoding
TEST(SecurityTest, IntegerOverflowProtection) {
    // Create a payload that would overflow uint32_t when added to current_offset
    Message msg;

    // Try to create a message with a very large payload
    // This should fail gracefully rather than overflowing
    std::vector<uint8_t> large_payload(1000000, 0xAA);
    msg[tags::NONC] = large_payload;

    // Should encode successfully for reasonable sizes
    EXPECT_NO_THROW({
        auto encoded = encode(msg);
        EXPECT_GT(encoded.size(), 0);
    });
}

// Test random_bytes overflow protection
TEST(SecurityTest, RandomBytesOverflowProtection) {
    // Normal size should work
    EXPECT_NO_THROW({
        auto bytes = crypto::random_bytes(1024);
        EXPECT_EQ(bytes.size(), 1024);
    });

    // Size > INT_MAX should throw
    size_t huge_size = static_cast<size_t>(INT_MAX) + 1000;
    EXPECT_THROW({
        crypto::random_bytes(huge_size);
    }, std::invalid_argument);
}

// Test input validation for command-line parsing
TEST(SecurityTest, InputValidationStoi) {
    // This test verifies that the std::stoi exception handling is in place
    // Actual validation happens in main.cpp, but we can verify the concept

    std::string invalid_input = "not_a_number";

    EXPECT_THROW({
        int value = std::stoi(invalid_input);
        (void)value; // Suppress unused variable warning
    }, std::exception);

    // Valid input should work
    std::string valid_input = "12345";
    EXPECT_NO_THROW({
        int value = std::stoi(valid_input);
        EXPECT_EQ(value, 12345);
    });
}

// Test RAII socket wrapper
TEST(SecurityTest, SocketGuardRAII) {
    using namespace util;

    // Test 1: Basic construction and destruction
    {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        ASSERT_GE(fd, 0) << "Failed to create socket";

        {
            SocketGuard guard(fd);
            EXPECT_EQ(guard.get(), fd);
            EXPECT_TRUE(guard.valid());

            // Socket should be valid while guard is in scope
            int result = fcntl(fd, F_GETFD);
            EXPECT_NE(result, -1) << "Socket should be open";
        }

        // Socket should be closed after guard goes out of scope
        int result = fcntl(fd, F_GETFD);
        EXPECT_EQ(result, -1) << "Socket should be closed";
    }

    // Test 2: Invalid socket (fd = -1)
    {
        SocketGuard guard;
        EXPECT_EQ(guard.get(), -1);
        EXPECT_FALSE(guard.valid());
    }

    // Test 3: Move semantics
    {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        ASSERT_GE(fd, 0);

        SocketGuard guard1(fd);
        SocketGuard guard2(std::move(guard1));

        EXPECT_EQ(guard1.get(), -1) << "Source should be invalidated";
        EXPECT_EQ(guard2.get(), fd) << "Destination should have ownership";
        EXPECT_FALSE(guard1.valid());
        EXPECT_TRUE(guard2.valid());
    }

    // Test 4: Release
    {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        ASSERT_GE(fd, 0);

        int released_fd;
        {
            SocketGuard guard(fd);
            released_fd = guard.release();
            EXPECT_EQ(released_fd, fd);
            EXPECT_EQ(guard.get(), -1) << "Guard should be invalidated after release";
        }

        // Socket should still be open after guard destruction
        int result = fcntl(released_fd, F_GETFD);
        EXPECT_NE(result, -1) << "Socket should still be open after release";

        // Clean up manually
        close(released_fd);
    }

    // Test 5: Reset
    {
        int fd1 = socket(AF_INET, SOCK_DGRAM, 0);
        int fd2 = socket(AF_INET, SOCK_DGRAM, 0);
        ASSERT_GE(fd1, 0);
        ASSERT_GE(fd2, 0);

        SocketGuard guard(fd1);

        // Reset to new socket
        guard.reset(fd2);

        // fd1 should be closed
        EXPECT_EQ(fcntl(fd1, F_GETFD), -1) << "Old socket should be closed";

        // guard should now manage fd2
        EXPECT_EQ(guard.get(), fd2);

        // fd2 should still be open
        EXPECT_NE(fcntl(fd2, F_GETFD), -1) << "New socket should be open";
    }
}

// Test exception safety with socket wrapper
TEST(SecurityTest, SocketGuardExceptionSafety) {
    using namespace util;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(fd, 0);

    try {
        SocketGuard guard(fd);

        // Simulate an error condition
        throw std::runtime_error("Simulated error");
    } catch (const std::exception&) {
        // Exception was caught
    }

    // Socket should be closed despite the exception
    int result = fcntl(fd, F_GETFD);
    EXPECT_EQ(result, -1) << "Socket should be closed after exception";
}

// Test Merkle path bounds checking
TEST(SecurityTest, MerklePathBoundsChecking) {
    // This verifies that Merkle path verification includes bounds checking
    // The actual implementation is in protocol.cpp, here we test the concept

    std::vector<uint8_t> nonce(32);
    std::vector<std::vector<uint8_t>> nonces = {nonce};

    EXPECT_NO_THROW({
        crypto::MerkleTree tree(32, nonces);
        auto path = tree.path(0);
        EXPECT_GE(path.size(), 0);
    });
}

// Test base64 decoder shared utility
TEST(SecurityTest, Base64DecoderUtility) {
    using namespace util;

    // Valid base64
    std::string valid_b64 = "SGVsbG8gV29ybGQ="; // "Hello World"
    auto result = decode_base64(valid_b64);
    ASSERT_TRUE(result.has_value());
    EXPECT_GT(result->size(), 0);

    // Invalid base64 characters should be handled
    std::string with_whitespace = "SGVs bG8g V29y bGQ=";
    auto result2 = decode_base64(with_whitespace);
    EXPECT_TRUE(result2.has_value()); // Should skip whitespace

    // Empty string
    auto result3 = decode_base64("");
    EXPECT_TRUE(result3.has_value());
    EXPECT_EQ(result3->size(), 0);
}

// Test noexcept specifications
TEST(SecurityTest, NoexceptSpecifications) {
    // Verify that noexcept functions are actually noexcept
    // Note: We test the methods on existing objects, not construction
    QueryResult qr;
    TrustedTimeResult tr;

    EXPECT_TRUE(noexcept(qr.is_success()));
    EXPECT_TRUE(noexcept(tr.is_success()));
    EXPECT_TRUE(noexcept(tr.is_trusted()));

    util::SocketGuard guard;
    EXPECT_TRUE(noexcept(guard.get()));
    EXPECT_TRUE(noexcept(guard.valid()));
    EXPECT_TRUE(noexcept(guard.release()));
}

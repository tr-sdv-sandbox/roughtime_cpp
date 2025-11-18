// Copyright 2024
// SPDX-License-Identifier: Apache-2.0
//
// Utility functions for Roughtime

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <unistd.h>

namespace roughtime {
namespace util {

// RAII wrapper for socket file descriptors
class SocketGuard {
public:
    SocketGuard() : fd_(-1) {}
    explicit SocketGuard(int fd) : fd_(fd) {}

    // Disable copy
    SocketGuard(const SocketGuard&) = delete;
    SocketGuard& operator=(const SocketGuard&) = delete;

    // Enable move
    SocketGuard(SocketGuard&& other) noexcept : fd_(other.fd_) {
        other.fd_ = -1;
    }

    SocketGuard& operator=(SocketGuard&& other) noexcept {
        if (this != &other) {
            reset();
            fd_ = other.fd_;
            other.fd_ = -1;
        }
        return *this;
    }

    ~SocketGuard() {
        reset();
    }

    void reset(int fd = -1) {
        if (fd_ >= 0) {
            close(fd_);
        }
        fd_ = fd;
    }

    int get() const noexcept { return fd_; }
    bool valid() const noexcept { return fd_ >= 0; }

    int release() noexcept {
        int fd = fd_;
        fd_ = -1;
        return fd;
    }

private:
    int fd_;
};

// Encode byte vector to base64 string
inline std::string encode_base64(const uint8_t* data, size_t len) {
    static const char base64_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string result;
    result.reserve(((len + 2) / 3) * 4);

    for (size_t i = 0; i < len; i += 3) {
        uint32_t val = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) val |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) val |= static_cast<uint32_t>(data[i + 2]);

        result.push_back(base64_chars[(val >> 18) & 0x3F]);
        result.push_back(base64_chars[(val >> 12) & 0x3F]);
        result.push_back((i + 1 < len) ? base64_chars[(val >> 6) & 0x3F] : '=');
        result.push_back((i + 2 < len) ? base64_chars[val & 0x3F] : '=');
    }

    return result;
}

// Decode base64 string to byte vector
// Returns std::nullopt if input is invalid
inline std::optional<std::vector<uint8_t>> decode_base64(const std::string& input) {
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::vector<uint8_t> result;
    std::vector<int> char_values(256, -1);

    for (size_t i = 0; i < base64_chars.size(); i++) {
        char_values[static_cast<uint8_t>(base64_chars[i])] = static_cast<int>(i);
    }

    int val = 0;
    int bits = -8;

    for (char c : input) {
        unsigned char uc = static_cast<unsigned char>(c);
        if (char_values[uc] == -1) {
            if (c == '=') break;
            continue;
        }

        val = (val << 6) + char_values[uc];
        bits += 6;

        if (bits >= 0) {
            result.push_back(static_cast<uint8_t>((val >> bits) & 0xFF));
            bits -= 8;
        }
    }

    return result;
}

}  // namespace util
}  // namespace roughtime

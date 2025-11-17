// Copyright 2024
// SPDX-License-Identifier: Apache-2.0
//
// Modern C++ implementation of Roughtime protocol
// Based on Cloudflare's Go implementation

#pragma once

#include "config.h"
#include <cstdint>
#include <map>
#include <string>
#include <vector>
#include <optional>
#include <chrono>
#include <array>

namespace roughtime {

// Protocol version enumeration
enum class Version : uint32_t {
    Google = 0,           // Google-Roughtime
    Draft07 = 0x80000007, // draft-ietf-ntp-roughtime-07
    Draft08 = 0x80000008, // draft-ietf-ntp-roughtime-08
    Draft11 = 0x8000000b  // draft-ietf-ntp-roughtime-11
};

std::string version_to_string(Version ver);

// Roughtime tags (4-byte identifiers)
constexpr uint32_t make_tag(const char tag[5]) {
    return static_cast<uint32_t>(tag[0]) |
           (static_cast<uint32_t>(tag[1]) << 8) |
           (static_cast<uint32_t>(tag[2]) << 16) |
           (static_cast<uint32_t>(tag[3]) << 24);
}

// Protocol constants
constexpr size_t MIN_REQUEST_SIZE = 1024;
constexpr size_t MAX_NONCE_SIZE = 64;
// Note: ED25519_PUBLIC_KEY_SIZE is defined in config.h
constexpr size_t ED25519_SIGNATURE_SIZE = 64;
constexpr size_t SHA512_HASH_SIZE = 64;

// Tag definitions
namespace tags {
    constexpr uint32_t CERT = make_tag("CERT");
    constexpr uint32_t DELE = make_tag("DELE");
    constexpr uint32_t INDX = make_tag("INDX");
    constexpr uint32_t MAXT = make_tag("MAXT");
    constexpr uint32_t MIDP = make_tag("MIDP");
    constexpr uint32_t MINT = make_tag("MINT");
    constexpr uint32_t NONC = make_tag("NONC");
    constexpr uint32_t PAD  = make_tag("PAD\xff");
    constexpr uint32_t PATH = make_tag("PATH");
    constexpr uint32_t PUBK = make_tag("PUBK");
    constexpr uint32_t RADI = make_tag("RADI");
    constexpr uint32_t ROOT = make_tag("ROOT");
    constexpr uint32_t SIG  = make_tag("SIG\x00");
    constexpr uint32_t SREP = make_tag("SREP");
    constexpr uint32_t SRV  = make_tag("SRV\x00");
    constexpr uint32_t VER  = make_tag("VER\x00");
    constexpr uint32_t ZZZZ = make_tag("ZZZZ");
}

// Type alias for protocol messages
using Message = std::map<uint32_t, std::vector<uint8_t>>;

// Encode a message into wire format
std::vector<uint8_t> encode(const Message& msg);

// Decode wire format into a message
std::optional<Message> decode(const std::vector<uint8_t>& data);

// Add IETF framing to a message
std::vector<uint8_t> encode_framed(bool version_ietf, const std::vector<uint8_t>& msg);

// Remove IETF framing and determine protocol version
struct DecodedFrame {
    std::vector<uint8_t> data;
    bool is_ietf;
};
std::optional<DecodedFrame> decode_framed(const std::vector<uint8_t>& data);

// Calculate nonce for chained requests
void calculate_chain_nonce(
    std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& prev_reply,
    const std::vector<uint8_t>& blind
);

// Request structure
struct Request {
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> blind;
    std::vector<uint8_t> request_bytes;
};

// Create a Roughtime request
std::optional<Request> create_request(
    const std::vector<Version>& version_preference,
    const std::vector<uint8_t>& prev_reply,
    const std::array<uint8_t, ED25519_PUBLIC_KEY_SIZE>& root_public_key
);

// Reply verification result
struct VerifiedReply {
    std::chrono::system_clock::time_point midpoint;
    std::chrono::microseconds radius;
};

// Verify a Roughtime reply
std::optional<VerifiedReply> verify_reply(
    const std::vector<Version>& version_preference,
    const std::vector<uint8_t>& reply_bytes,
    const std::array<uint8_t, ED25519_PUBLIC_KEY_SIZE>& public_key,
    const std::vector<uint8_t>& nonce
);

// Utility functions
size_t nonce_size(bool version_ietf);
size_t message_overhead(bool version_ietf, size_t num_tags);
std::vector<Version> advertised_versions_from_preference(
    const std::vector<Version>& preference
);

} // namespace roughtime

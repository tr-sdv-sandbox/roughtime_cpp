// Copyright 2024
// SPDX-License-Identifier: Apache-2.0
//
// Roughtime Server Implementation
// Based on Cloudflare's Go implementation

#pragma once

#include <roughtime/config.h>
#include <roughtime/protocol.h>
#include <roughtime/rate_limiter.h>
#include <cstdint>
#include <string>
#include <vector>
#include <array>
#include <chrono>
#include <memory>

namespace roughtime {
namespace server {

// Certificate that delegates from root key to online key
struct Certificate {
    std::vector<uint8_t> bytes_ietf;      // IETF-Roughtime certificate
    std::vector<uint8_t> bytes_google;    // Google-Roughtime certificate
    std::array<uint8_t, ED25519_PUBLIC_KEY_SIZE> online_public_key;
    std::array<uint8_t, 64> online_private_key;  // Ed25519 private key (64 bytes)
    std::vector<uint8_t> srv_hash;        // Hash for SRV tag
};

// Create a delegation certificate
// Delegates from root_private_key to online_public_key for time range [min_time, max_time]
std::optional<Certificate> create_certificate(
    std::chrono::system_clock::time_point min_time,
    std::chrono::system_clock::time_point max_time,
    const std::array<uint8_t, ED25519_PUBLIC_KEY_SIZE>& online_public_key,
    const std::array<uint8_t, 64>& online_private_key,
    const std::array<uint8_t, 64>& root_private_key
);

// Server configuration
struct ServerConfig {
    std::string address;
    uint16_t port;
    std::array<uint8_t, 64> root_private_key;
    std::chrono::seconds radius;  // Uncertainty radius
    std::chrono::hours cert_validity;  // Certificate validity duration
    RateLimitConfig rate_limit;  // Rate limiting configuration
};

// Parsed client request
struct ParsedRequest {
    std::vector<uint8_t> nonce;
    std::vector<Version> versions;
    std::vector<uint8_t> srv;  // Optional SRV tag
    Version response_version;
};

// Parse a client request
std::optional<ParsedRequest> parse_request(const std::vector<uint8_t>& request_bytes);

// Create responses for a batch of requests
std::vector<std::vector<uint8_t>> create_replies(
    const std::vector<ParsedRequest>& requests,
    std::chrono::system_clock::time_point midpoint,
    std::chrono::seconds radius,
    const Certificate& cert
);

// Roughtime server
class Server {
public:
    Server(const ServerConfig& config);
    ~Server();

    // Run the server (blocking)
    void run();

    // Stop the server
    void stop();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// Key generation utilities
namespace keygen {
    // Generate Ed25519 keypair
    struct KeyPair {
        std::array<uint8_t, ED25519_PUBLIC_KEY_SIZE> public_key;
        std::array<uint8_t, 64> private_key;
    };

    KeyPair generate_keypair();

    // Generate keypair from seed (for deterministic keys)
    KeyPair keypair_from_seed(const std::array<uint8_t, 32>& seed);
}

} // namespace server
} // namespace roughtime

// Copyright 2024
// SPDX-License-Identifier: Apache-2.0
//
// Roughtime server configuration

#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>
#include <optional>

namespace roughtime {

// Constant for Ed25519 public key size
inline constexpr size_t ED25519_PUBLIC_KEY_SIZE = 32;

// Server address
struct ServerAddress {
    std::string protocol;  // "udp", "udp4", "udp6"
    std::string address;   // "host:port"
};

// Server configuration
struct Server {
    std::string name;
    std::string version;  // "IETF-Roughtime" or "Google-Roughtime"
    std::string public_key_type;  // "ed25519"
    std::array<uint8_t, ED25519_PUBLIC_KEY_SIZE> public_key;
    std::vector<ServerAddress> addresses;
};

// Parse server configuration from JSON
struct ParseConfigResult {
    std::vector<Server> servers;
    size_t skipped;
};

std::optional<ParseConfigResult> parse_config(const std::string& json_data);
std::optional<ParseConfigResult> load_config(const std::string& config_file);

} // namespace roughtime

// Copyright 2024
// SPDX-License-Identifier: Apache-2.0

#include "roughtime/config.h"
#include "roughtime/util.h"
#include <nlohmann/json.hpp>
#include <glog/logging.h>
#include <fstream>
#include <sstream>
#include <set>

using json = nlohmann::json;

namespace roughtime {

namespace {
    std::optional<std::array<uint8_t, ED25519_PUBLIC_KEY_SIZE>> decode_base64(
        const std::string& input
    ) {
        auto decoded = util::decode_base64(input);
        if (!decoded || decoded->size() != ED25519_PUBLIC_KEY_SIZE) {
            return std::nullopt;
        }

        std::array<uint8_t, ED25519_PUBLIC_KEY_SIZE> key;
        std::copy_n(decoded->begin(), ED25519_PUBLIC_KEY_SIZE, key.begin());
        return key;
    }
}

std::optional<ParseConfigResult> parse_config(const std::string& json_data) {
    try {
        auto j = json::parse(json_data);

        ParseConfigResult result;
        result.skipped = 0;

        if (!j.contains("servers") || !j["servers"].is_array()) {
            return std::nullopt;
        }

        std::set<std::string> seen_names;

        for (const auto& server_json : j["servers"]) {
            if (!server_json.contains("name") || !server_json["name"].is_string()) {
                continue;
            }

            std::string name = server_json["name"];

            // Check for duplicate names
            if (seen_names.count(name)) {
                return std::nullopt; // Duplicate name
            }
            seen_names.insert(name);

            // Check public key type
            if (!server_json.contains("publicKeyType") ||
                server_json["publicKeyType"] != "ed25519") {
                result.skipped++;
                continue;
            }

            // Parse public key
            if (!server_json.contains("publicKey") || !server_json["publicKey"].is_string()) {
                result.skipped++;
                continue;
            }

            auto public_key = decode_base64(server_json["publicKey"]);
            if (!public_key) {
                result.skipped++;
                continue;
            }

            // Parse addresses
            if (!server_json.contains("addresses") || !server_json["addresses"].is_array()) {
                result.skipped++;
                continue;
            }

            std::vector<ServerAddress> addresses;
            bool has_udp = false;

            for (const auto& addr_json : server_json["addresses"]) {
                if (!addr_json.contains("protocol") || !addr_json.contains("address")) {
                    continue;
                }

                ServerAddress addr;
                addr.protocol = addr_json["protocol"];
                addr.address = addr_json["address"];

                if (addr.protocol == "udp" || addr.protocol == "udp4" || addr.protocol == "udp6") {
                    has_udp = true;
                }

                addresses.push_back(std::move(addr));
            }

            if (!has_udp) {
                result.skipped++;
                continue;
            }

            // Create server
            Server server;
            server.name = name;
            server.public_key = *public_key;
            server.public_key_type = "ed25519";
            server.addresses = std::move(addresses);

            // Parse version (optional)
            if (server_json.contains("version") && server_json["version"].is_string()) {
                server.version = server_json["version"];
            } else {
                server.version = "Google-Roughtime"; // Default
            }

            result.servers.push_back(std::move(server));
        }

        return result;
    } catch (const std::exception& e) {
        LOG(ERROR) << "parse_config failed: " << e.what();
        return std::nullopt;
    }
}

std::optional<ParseConfigResult> load_config(const std::string& config_file) {
    try {
        std::ifstream file(config_file);
        if (!file.is_open()) {
            return std::nullopt;
        }

        std::stringstream buffer;
        buffer << file.rdbuf();

        return parse_config(buffer.str());
    } catch (const std::exception& e) {
        LOG(ERROR) << "load_config failed: " << e.what();
        return std::nullopt;
    }
}

} // namespace roughtime

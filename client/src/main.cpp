// Copyright 2024
// SPDX-License-Identifier: Apache-2.0
//
// Roughtime client command-line tool

#include "roughtime/client.h"
#include "roughtime/config.h"
#include "roughtime/protocol.h"
#include "roughtime/util.h"
#include <glog/logging.h>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <getopt.h>

using namespace roughtime;

namespace {
    constexpr const char* VERSION = "1.0.0";
    constexpr const char* BUILD_TIME = __DATE__ " " __TIME__;

    void print_version() {
        std::cout << "getroughtime " << VERSION << " (C++17) built " << BUILD_TIME << "\n";
    }

    void print_usage(const char* program_name) {
        std::cout << "Usage: " << program_name << " [OPTIONS]\n\n"
                  << "Options:\n"
                  << "  -c, --config FILE      JSON configuration file with server list\n"
                  << "  -p, --ping ADDR        Ping a single server (e.g., localhost:2002)\n"
                  << "  -k, --pubkey KEY       Base64-encoded Ed25519 public key for ping\n"
                  << "  -v, --ping-version VER Version for ping (IETF-Roughtime or Google-Roughtime)\n"
                  << "  -a, --attempts NUM     Number of query attempts per server (default: 3)\n"
                  << "  -t, --timeout MS       Timeout in milliseconds (default: 1000)\n"
                  << "  -V, --version          Print version and exit\n"
                  << "  -h, --help             Show this help message\n";
    }

    std::string format_duration(std::chrono::microseconds duration) {
        using namespace std::chrono;

        auto s = duration_cast<seconds>(duration);
        auto ms = duration_cast<milliseconds>(duration - s);
        auto us = duration_cast<microseconds>(duration - s - ms);

        std::ostringstream oss;
        if (s.count() > 0) {
            oss << s.count() << "s";
        }
        if (ms.count() > 0) {
            if (s.count() > 0) oss << " ";
            oss << ms.count() << "ms";
        }
        if (us.count() > 0 && s.count() == 0) {
            if (ms.count() > 0) oss << " ";
            oss << us.count() << "µs";
        }
        return oss.str();
    }

    std::string format_time(std::chrono::system_clock::time_point tp) {
        auto time_t = std::chrono::system_clock::to_time_t(tp);
        std::ostringstream oss;
        oss << std::put_time(std::gmtime(&time_t), "%Y-%m-%d %H:%M:%S UTC");
        return oss.str();
    }

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

int main(int argc, char* argv[]) {
    // Initialize Google's logging library
    FLAGS_logtostderr = 1;
    FLAGS_minloglevel = 0;  // INFO level
    google::InitGoogleLogging(argv[0]);

    std::string config_file;
    std::string ping_addr;
    std::string ping_pubkey;
    std::string ping_version = "Google-Roughtime";
    int attempts = 3;
    int timeout_ms = 1000;
    bool show_version = false;

    static struct option long_options[] = {
        {"config", required_argument, 0, 'c'},
        {"ping", required_argument, 0, 'p'},
        {"pubkey", required_argument, 0, 'k'},
        {"ping-version", required_argument, 0, 'v'},
        {"attempts", required_argument, 0, 'a'},
        {"timeout", required_argument, 0, 't'},
        {"version", no_argument, 0, 'V'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "c:p:k:v:a:t:Vh", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'c':
                config_file = optarg;
                break;
            case 'p':
                ping_addr = optarg;
                break;
            case 'k':
                ping_pubkey = optarg;
                break;
            case 'v':
                ping_version = optarg;
                break;
            case 'a':
                try {
                    attempts = std::stoi(optarg);
                } catch (const std::exception& e) {
                    std::cerr << "Error: Invalid attempts value: " << optarg << "\n";
                    return 1;
                }
                break;
            case 't':
                try {
                    timeout_ms = std::stoi(optarg);
                } catch (const std::exception& e) {
                    std::cerr << "Error: Invalid timeout value: " << optarg << "\n";
                    return 1;
                }
                break;
            case 'V':
                show_version = true;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (show_version) {
        print_version();
        return 0;
    }

    Client client;

    // Handle config file mode
    if (!config_file.empty()) {
        auto config_result = load_config(config_file);
        if (!config_result) {
            std::cerr << "Error: Failed to load config file: " << config_file << "\n";
            return 1;
        }

        if (config_result->servers.empty()) {
            std::cerr << "Error: No suitable servers in config file\n";
            return 1;
        }

        if (config_result->skipped > 0) {
            std::cerr << "Warning: Skipped " << config_result->skipped << " servers\n";
        }

        auto result = client.query_for_trusted_time(
            config_result->servers,
            3,  // minimum 3 servers for trust
            attempts,
            std::chrono::milliseconds(timeout_ms),
            std::chrono::seconds(120)  // radius threshold: 2 minutes
        );

        // Show individual server results
        for (const auto& r : result.all_results) {
            if (r.is_success()) {
                std::cout << r.server->name << ": "
                         << format_time(r.midpoint) << " ±"
                         << format_duration(r.radius)
                         << " (in " << r.network_delay.count() << "ms)\n";
            } else {
                std::cerr << "skipped " << r.server->name << ": "
                         << r.error << "\n";
            }
        }

        if (!result.is_success()) {
            std::cerr << "Error: " << result.error << "\n";
            return 1;
        }

        std::cout << "\nTrusted time: " << format_time(result.time)
                  << " ±" << format_duration(result.uncertainty)
                  << " (" << result.agreeing_servers << "/" << result.total_queried
                  << " servers";

        if (result.is_trusted()) {
            std::cout << ", TRUSTED)\n";
        } else {
            std::cout << ", NOT TRUSTED - need at least 3 agreeing servers)\n";
            return 1;
        }

        return 0;
    }

    // Handle ping mode
    if (!ping_addr.empty()) {
        if (ping_pubkey.empty()) {
            std::cerr << "Error: Ping requires -k/--pubkey\n";
            return 1;
        }

        auto public_key = decode_base64(ping_pubkey);
        if (!public_key) {
            std::cerr << "Error: Invalid public key (must be base64-encoded 32 bytes)\n";
            return 1;
        }

        if (ping_version != "Google-Roughtime" && ping_version != "IETF-Roughtime") {
            std::cerr << "Error: Invalid ping version (use Google-Roughtime or IETF-Roughtime)\n";
            return 1;
        }

        Server server;
        server.name = "ping";
        server.version = ping_version;
        server.public_key_type = "ed25519";
        server.public_key = *public_key;
        server.addresses.push_back({"udp", ping_addr});

        auto result = client.query(
            server,
            attempts,
            std::chrono::milliseconds(timeout_ms)
        );

        if (result.is_success()) {
            std::cout << "Ping response: "
                     << format_time(result.midpoint) << " ±"
                     << format_duration(result.radius)
                     << " (in " << result.network_delay.count() << "ms)\n";
            return 0;
        } else {
            std::cerr << "Ping error: " << result.error << "\n";
            return 1;
        }
    }

    std::cerr << "Error: Either provide -c/--config or -p/--ping\n";
    print_usage(argv[0]);
    return 1;
}

// Copyright 2024
// SPDX-License-Identifier: Apache-2.0
//
// Roughtime Server - Main executable

#include "roughtime/server.h"
#include <roughtime/crypto.h>
#include <roughtime/util.h>
#include <glog/logging.h>
#include <nlohmann/json.hpp>
#include <getopt.h>
#include <iostream>
#include <fstream>
#include <csignal>
#include <iomanip>

using namespace roughtime;
using json = nlohmann::json;

namespace {
    server::Server* g_server = nullptr;

    void signal_handler(int signal) {
        if (signal == SIGINT || signal == SIGTERM) {
            LOG(INFO) << "Received signal " << signal << ", shutting down...";
            if (g_server) {
                g_server->stop();
            }
        }
    }

    void print_usage(const char* program) {
        std::cout << "Roughtime Server - IETF Roughtime Protocol Implementation\n\n";
        std::cout << "Usage: " << program << " [options]\n\n";
        std::cout << "Options:\n";
        std::cout << "  --config FILE         Load server configuration from JSON file\n";
        std::cout << "  --addr ADDRESS        Address to listen on (default: 127.0.0.1)\n";
        std::cout << "  --port PORT           Port to listen on (default: 2002)\n";
        std::cout << "  --root-key SEED       Hex-encoded 32-byte root key seed (generates random if not specified)\n";
        std::cout << "  --radius SECONDS      Uncertainty radius in seconds (default: 1)\n";
        std::cout << "  --cert-validity HOURS Certificate validity in hours (default: 48)\n";
        std::cout << "  --help                Show this help message\n";
        std::cout << "  --version             Show version information\n";
        std::cout << "\nExamples:\n";
        std::cout << "  # Load from config file:\n";
        std::cout << "  " << program << " --config server1.json\n\n";
        std::cout << "  # Manual configuration:\n";
        std::cout << "  " << program << " --addr 0.0.0.0 --port 2002\n";
        std::cout << "  " << program << " --root-key 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n";
        std::cout << "\n";
    }

    void print_version() {
        std::cout << "Roughtime Server v1.0.0\n";
        std::cout << "IETF Roughtime Draft 07/08/11/14 + Google-Roughtime\n";
        std::cout << "Copyright 2024 - Apache License 2.0\n";
    }

    std::optional<server::ServerConfig> load_config_from_file(const std::string& config_file) {
        try {
            std::ifstream file(config_file);
            if (!file.is_open()) {
                LOG(ERROR) << "Failed to open config file: " << config_file;
                return std::nullopt;
            }

            json j;
            file >> j;

            server::ServerConfig config;
            config.address = j.value("address", "127.0.0.1");
            config.port = static_cast<uint16_t>(j.value("port", 2002));
            config.radius = std::chrono::seconds(j.value("radius", 1));
            config.cert_validity = std::chrono::hours(j.value("certValidity", 48));

            // Parse root key seed
            std::string seed_hex = j.value("rootKeySeed", "");
            if (seed_hex.empty()) {
                LOG(ERROR) << "Config file missing rootKeySeed";
                return std::nullopt;
            }

            if (seed_hex.length() != 64) {
                LOG(ERROR) << "Root key seed must be exactly 32 bytes (64 hex characters)";
                return std::nullopt;
            }

            std::array<uint8_t, 32> seed;
            for (size_t i = 0; i < 32; i++) {
                unsigned int byte;
                if (sscanf(seed_hex.c_str() + i * 2, "%2x", &byte) != 1) {
                    LOG(ERROR) << "Invalid hex in root key seed";
                    return std::nullopt;
                }
                seed[i] = static_cast<uint8_t>(byte);
            }

            auto kp = server::keygen::keypair_from_seed(seed);
            config.root_private_key = kp.private_key;

            LOG(INFO) << "Loaded server config from: " << config_file;
            std::cout << "Server: " << j.value("name", "unknown") << "\n";
            std::cout << "Address: " << config.address << ":" << config.port << "\n";
            std::cout << "Public Key: " << j.value("publicKey", "unknown") << "\n\n";

            return config;
        } catch (const std::exception& e) {
            LOG(ERROR) << "Error loading config file: " << e.what();
            return std::nullopt;
        }
    }

    std::array<uint8_t, 64> generate_or_load_root_key(const std::string& seed_hex) {
        std::array<uint8_t, 64> root_private_key;

        if (seed_hex.empty()) {
            // Generate random root key
            std::array<uint8_t, 32> seed;
            crypto::random_bytes(seed.data(), seed.size());

            auto kp = server::keygen::keypair_from_seed(seed);
            root_private_key = kp.private_key;

            LOG(INFO) << "Generated new root key";
            std::cout << "Root key seed (save this!): ";
            for (auto b : seed) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
            }
            std::cout << std::dec << "\n";

            std::cout << "Root public key (base64): "
                      << util::encode_base64(kp.public_key.data(), kp.public_key.size()) << "\n";
            std::cout << "Root public key (hex):    ";
            for (auto b : kp.public_key) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
            }
            std::cout << std::dec << "\n\n";

        } else {
            // Parse hex seed
            if (seed_hex.length() != 64) {
                throw std::runtime_error("Root key seed must be exactly 32 bytes (64 hex characters)");
            }

            std::array<uint8_t, 32> seed;
            for (size_t i = 0; i < 32; i++) {
                unsigned int byte;
                if (sscanf(seed_hex.c_str() + i * 2, "%2x", &byte) != 1) {
                    throw std::runtime_error("Invalid hex in root key seed");
                }
                seed[i] = static_cast<uint8_t>(byte);
            }

            auto kp = server::keygen::keypair_from_seed(seed);
            root_private_key = kp.private_key;

            LOG(INFO) << "Loaded root key from seed";
            std::cout << "Root public key (base64): "
                      << util::encode_base64(kp.public_key.data(), kp.public_key.size()) << "\n";
            std::cout << "Root public key (hex):    ";
            for (auto b : kp.public_key) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
            }
            std::cout << std::dec << "\n\n";
        }

        return root_private_key;
    }
}

int main(int argc, char* argv[]) {
    // Initialize logging
    FLAGS_logtostderr = 1;
    FLAGS_minloglevel = 0;  // INFO level
    google::InitGoogleLogging(argv[0]);

    // Parse command line arguments
    std::string config_file;
    std::string address = "127.0.0.1";
    int port = 2002;
    std::string root_key_seed;
    int radius_seconds = 1;
    int cert_validity_hours = 48;

    struct option long_options[] = {
        {"config", required_argument, 0, 'f'},
        {"addr", required_argument, 0, 'a'},
        {"port", required_argument, 0, 'p'},
        {"root-key", required_argument, 0, 'k'},
        {"radius", required_argument, 0, 'r'},
        {"cert-validity", required_argument, 0, 'c'},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "f:a:p:k:r:c:hv", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'f':
                config_file = optarg;
                break;
            case 'a':
                address = optarg;
                break;
            case 'p':
                try {
                    port = std::stoi(optarg);
                    if (port < 1 || port > 65535) {
                        std::cerr << "Invalid port number: " << port << "\n";
                        return 1;
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Error: Invalid port value: " << optarg << "\n";
                    return 1;
                }
                break;
            case 'k':
                root_key_seed = optarg;
                break;
            case 'r':
                try {
                    radius_seconds = std::stoi(optarg);
                    if (radius_seconds < 0) {
                        std::cerr << "Radius must be non-negative\n";
                        return 1;
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Error: Invalid radius value: " << optarg << "\n";
                    return 1;
                }
                break;
            case 'c':
                try {
                    cert_validity_hours = std::stoi(optarg);
                    if (cert_validity_hours <= 0) {
                        std::cerr << "Certificate validity must be positive\n";
                        return 1;
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Error: Invalid certificate validity value: " << optarg << "\n";
                    return 1;
                }
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 'v':
                print_version();
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    try {
        server::ServerConfig config;

        // Load config from file or use command line args
        if (!config_file.empty()) {
            // Load from JSON config file
            auto loaded_config = load_config_from_file(config_file);
            if (!loaded_config) {
                std::cerr << "Failed to load config from file: " << config_file << "\n";
                return 1;
            }
            config = *loaded_config;
        } else {
            // Generate or load root key from command line
            auto root_private_key = generate_or_load_root_key(root_key_seed);

            // Create server configuration from command line args
            config.address = address;
            config.port = static_cast<uint16_t>(port);
            config.root_private_key = root_private_key;
            config.radius = std::chrono::seconds(radius_seconds);
            config.cert_validity = std::chrono::hours(cert_validity_hours);
        }

        // Create and start server
        server::Server server(config);
        g_server = &server;

        // Set up signal handlers
        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);

        LOG(INFO) << "Starting Roughtime server...";
        LOG(INFO) << "Address: " << address << ":" << port;
        LOG(INFO) << "Radius: " << radius_seconds << " seconds";
        LOG(INFO) << "Certificate validity: " << cert_validity_hours << " hours";

        server.run();

        LOG(INFO) << "Server stopped";

    } catch (const std::exception& e) {
        LOG(ERROR) << "Fatal error: " << e.what();
        return 1;
    }

    return 0;
}

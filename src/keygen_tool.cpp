// Copyright 2024
// SPDX-License-Identifier: Apache-2.0
//
// Roughtime Key Generation Tool
// Generates server configuration files with Ed25519 keypairs

#include <roughtime/crypto.h>
#include <roughtime/util.h>
#include <roughtime/server.h>
#include <nlohmann/json.hpp>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <getopt.h>

using json = nlohmann::json;
using namespace roughtime;

void print_usage(const char* program) {
    std::cout << "Roughtime Key Generation Tool\n\n";
    std::cout << "Usage: " << program << " [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -o, --output FILE     Output JSON config file (default: server_config.json)\n";
    std::cout << "  -n, --name NAME       Server name (default: roughtime-server)\n";
    std::cout << "  -a, --addr ADDRESS    Listen address (default: 127.0.0.1)\n";
    std::cout << "  -p, --port PORT       Listen port (default: 2002)\n";
    std::cout << "  -r, --radius SECONDS  Uncertainty radius in seconds (default: 1)\n";
    std::cout << "  -c, --cert-hours HOURS Certificate validity in hours (default: 48)\n";
    std::cout << "  -s, --seed HEX        32-byte hex seed for deterministic key (generates random if not specified)\n";
    std::cout << "  -h, --help            Show this help message\n";
    std::cout << "\nExamples:\n";
    std::cout << "  # Generate a new server config with random key:\n";
    std::cout << "  " << program << " -o server1.json -n server1 -p 2002\n\n";
    std::cout << "  # Generate from specific seed:\n";
    std::cout << "  " << program << " -o server1.json -s 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n";
    std::cout << "\n";
}

int main(int argc, char* argv[]) {
    std::string output_file = "server_config.json";
    std::string name = "roughtime-server";
    std::string address = "127.0.0.1";
    int port = 2002;
    int radius_seconds = 1;
    int cert_validity_hours = 48;
    std::string seed_hex;

    struct option long_options[] = {
        {"output", required_argument, 0, 'o'},
        {"name", required_argument, 0, 'n'},
        {"addr", required_argument, 0, 'a'},
        {"port", required_argument, 0, 'p'},
        {"radius", required_argument, 0, 'r'},
        {"cert-hours", required_argument, 0, 'c'},
        {"seed", required_argument, 0, 's'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "o:n:a:p:r:c:s:h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'o':
                output_file = optarg;
                break;
            case 'n':
                name = optarg;
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
            case 's':
                seed_hex = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    try {
        // Generate or load seed
        std::array<uint8_t, 32> seed;

        if (seed_hex.empty()) {
            // Generate random seed
            crypto::random_bytes(seed.data(), seed.size());
            std::cout << "Generated random seed\n";
        } else {
            // Parse hex seed
            if (seed_hex.length() != 64) {
                std::cerr << "Error: Seed must be exactly 32 bytes (64 hex characters)\n";
                return 1;
            }

            for (size_t i = 0; i < 32; i++) {
                unsigned int byte;
                if (sscanf(seed_hex.c_str() + i * 2, "%2x", &byte) != 1) {
                    std::cerr << "Error: Invalid hex in seed\n";
                    return 1;
                }
                seed[i] = static_cast<uint8_t>(byte);
            }
            std::cout << "Using provided seed\n";
        }

        // Generate keypair from seed
        auto keypair = server::keygen::keypair_from_seed(seed);

        // Create JSON config
        json config;
        config["name"] = name;
        config["address"] = address;
        config["port"] = port;
        config["radius"] = radius_seconds;
        config["certValidity"] = cert_validity_hours;

        // Store the seed as hex
        std::stringstream seed_stream;
        for (auto b : seed) {
            seed_stream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        }
        config["rootKeySeed"] = seed_stream.str();

        // Store public key as base64
        config["publicKey"] = util::encode_base64(keypair.public_key.data(), keypair.public_key.size());
        config["publicKeyType"] = "ed25519";

        // Write to file
        std::ofstream outfile(output_file);
        if (!outfile) {
            std::cerr << "Error: Failed to open output file: " << output_file << "\n";
            return 1;
        }
        outfile << config.dump(2) << "\n";
        outfile.close();

        std::cout << "\n=== Server Configuration Generated ===\n";
        std::cout << "Name:              " << name << "\n";
        std::cout << "Address:           " << address << ":" << port << "\n";
        std::cout << "Radius:            " << radius_seconds << " seconds\n";
        std::cout << "Cert Validity:     " << cert_validity_hours << " hours\n";
        std::cout << "\nRoot Key Seed (hex):\n  " << seed_stream.str() << "\n";
        std::cout << "\nPublic Key (base64):\n  " << config["publicKey"] << "\n";
        std::cout << "\nPublic Key (hex):\n  ";
        for (auto b : keypair.public_key) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        }
        std::cout << std::dec << "\n";
        std::cout << "\nConfig saved to: " << output_file << "\n";
        std::cout << "\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}

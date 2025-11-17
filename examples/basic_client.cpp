// Example: Basic Roughtime client usage
// Build: g++ -std=c++17 basic_client.cpp -lroughtime -lsodium -o basic_client

#include <roughtime/client.h>
#include <roughtime/config.h>
#include <roughtime/protocol.h>
#include <iostream>
#include <iomanip>

std::string format_time(std::chrono::system_clock::time_point tp) {
    auto time_t = std::chrono::system_clock::to_time_t(tp);
    std::ostringstream oss;
    oss << std::put_time(std::gmtime(&time_t), "%Y-%m-%d %H:%M:%S UTC");
    return oss.str();
}

int main() {
    // Create a simple server configuration
    roughtime::Server server;
    server.name = "Cloudflare-Roughtime";
    server.version = "IETF-Roughtime";
    server.public_key_type = "ed25519";

    // Base64-decoded public key for Cloudflare
    // This is just an example - in production, decode from base64
    std::array<uint8_t, 32> pubkey = {
        0x80, 0x3e, 0xb7, 0x85, 0x28, 0xf7, 0x49, 0xc4,
        0xbe, 0xc2, 0xe3, 0x9e, 0x1a, 0xbb, 0x9b, 0x5e,
        0x5a, 0xb7, 0xe4, 0xdd, 0x5c, 0xe4, 0xb6, 0xf2,
        0xfd, 0x2f, 0x93, 0xec, 0xc3, 0x53, 0x8f, 0x1a
    };
    server.public_key = pubkey;

    server.addresses.push_back({"udp", "roughtime.cloudflare.com:2002"});

    // Create client and query
    roughtime::Client client;
    std::cout << "Querying " << server.name << "...\n";

    auto result = client.query(server);

    if (result.is_success()) {
        std::cout << "Success!\n";
        std::cout << "  Time: " << format_time(result.midpoint) << "\n";
        std::cout << "  Radius: ±"
                  << std::chrono::duration_cast<std::chrono::seconds>(result.radius).count()
                  << "s\n";
        std::cout << "  Network delay: " << result.network_delay.count() << "ms\n";
    } else {
        std::cerr << "Error: " << result.error << "\n";
        return 1;
    }

    return 0;
}

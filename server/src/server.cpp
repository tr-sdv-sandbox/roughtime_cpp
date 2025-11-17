// Copyright 2024
// SPDX-License-Identifier: Apache-2.0

#include "roughtime/server.h"
#include <roughtime/crypto.h>
#include <roughtime/validation.h>
#include <roughtime/rate_limiter.h>
#include <roughtime/openssl_wrappers.h>
#include <glog/logging.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <stdexcept>
#include <algorithm>
#include <atomic>

namespace roughtime {
namespace server {

namespace {
    constexpr const char* CERTIFICATE_CONTEXT = "RoughTime v1 delegation signature--\x00";
    constexpr size_t CERTIFICATE_CONTEXT_LEN = 36;
    constexpr const char* SIGNED_RESPONSE_CONTEXT = "RoughTime v1 response signature\x00";
    constexpr size_t SIGNED_RESPONSE_CONTEXT_LEN = 32;

    // Helper function to sign data with Ed25519 using OpenSSL
    void ed25519_sign(
        std::array<uint8_t, 64>& signature,
        const uint8_t* message,
        size_t message_len,
        const uint8_t* private_key
    ) {
        using namespace crypto;

        // Create EVP_PKEY from raw Ed25519 private key
        EVPPKey pkey(EVP_PKEY_new_raw_private_key(
            EVP_PKEY_ED25519,
            nullptr,
            private_key,
            32  // Ed25519 private key is 32 bytes
        ));
        if (!pkey) {
            throw std::runtime_error("Failed to create EVP_PKEY from private key");
        }

        // Create signing context
        EVPMDContext ctx;

        // Initialize signing (Ed25519 doesn't use a digest algorithm)
        if (EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get()) != 1) {
            throw std::runtime_error("Failed to initialize signing");
        }

        // Sign the message
        size_t sig_len = signature.size();
        if (EVP_DigestSign(ctx.get(), signature.data(), &sig_len, message, message_len) != 1) {
            throw std::runtime_error("Failed to sign message");
        }
    }

    void write_le32(uint8_t* data, uint32_t value) {
        data[0] = static_cast<uint8_t>(value & 0xff);
        data[1] = static_cast<uint8_t>((value >> 8) & 0xff);
        data[2] = static_cast<uint8_t>((value >> 16) & 0xff);
        data[3] = static_cast<uint8_t>((value >> 24) & 0xff);
    }

    void write_le64(uint8_t* data, uint64_t value) {
        data[0] = static_cast<uint8_t>(value & 0xff);
        data[1] = static_cast<uint8_t>((value >> 8) & 0xff);
        data[2] = static_cast<uint8_t>((value >> 16) & 0xff);
        data[3] = static_cast<uint8_t>((value >> 24) & 0xff);
        data[4] = static_cast<uint8_t>((value >> 32) & 0xff);
        data[5] = static_cast<uint8_t>((value >> 40) & 0xff);
        data[6] = static_cast<uint8_t>((value >> 48) & 0xff);
        data[7] = static_cast<uint8_t>((value >> 56) & 0xff);
    }

    uint32_t read_le32(const uint8_t* data) {
        return static_cast<uint32_t>(data[0]) |
               (static_cast<uint32_t>(data[1]) << 8) |
               (static_cast<uint32_t>(data[2]) << 16) |
               (static_cast<uint32_t>(data[3]) << 24);
    }
}

// Key generation
namespace keygen {
    KeyPair generate_keypair() {
        using namespace crypto;
        KeyPair kp;

        // Generate Ed25519 keypair using OpenSSL
        EVPPKeyContext ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr));
        if (!ctx) {
            throw std::runtime_error("Failed to create EVP_PKEY_CTX");
        }

        if (EVP_PKEY_keygen_init(ctx.get()) != 1) {
            throw std::runtime_error("Failed to initialize keygen");
        }

        EVP_PKEY* pkey_raw = nullptr;
        if (EVP_PKEY_keygen(ctx.get(), &pkey_raw) != 1) {
            throw std::runtime_error("Failed to generate keypair");
        }
        EVPPKey pkey(pkey_raw);

        // Extract raw public key
        size_t pub_len = 32;
        if (EVP_PKEY_get_raw_public_key(pkey.get(), kp.public_key.data(), &pub_len) != 1 || pub_len != 32) {
            throw std::runtime_error("Failed to extract public key");
        }

        // Extract raw private key
        size_t priv_len = 32;
        if (EVP_PKEY_get_raw_private_key(pkey.get(), kp.private_key.data(), &priv_len) != 1 || priv_len != 32) {
            throw std::runtime_error("Failed to extract private key");
        }

        // OpenSSL stores only 32-byte seed for Ed25519 private key
        // For compatibility with existing code that expects 64 bytes, we duplicate:
        // First 32 bytes = private key seed, last 32 bytes = public key
        std::copy(kp.public_key.begin(), kp.public_key.end(), kp.private_key.begin() + 32);

        return kp;
    }

    KeyPair keypair_from_seed(const std::array<uint8_t, 32>& seed) {
        using namespace crypto;
        KeyPair kp;

        // Create EVP_PKEY from seed (private key)
        EVPPKey pkey(EVP_PKEY_new_raw_private_key(
            EVP_PKEY_ED25519,
            nullptr,
            seed.data(),
            32
        ));
        if (!pkey) {
            throw std::runtime_error("Failed to create EVP_PKEY from seed");
        }

        // Extract raw public key
        size_t pub_len = 32;
        if (EVP_PKEY_get_raw_public_key(pkey.get(), kp.public_key.data(), &pub_len) != 1 || pub_len != 32) {
            throw std::runtime_error("Failed to extract public key from seed");
        }

        // Use the seed as private key (32 bytes) + public key (32 bytes)
        std::copy(seed.begin(), seed.end(), kp.private_key.begin());
        std::copy(kp.public_key.begin(), kp.public_key.end(), kp.private_key.begin() + 32);

        return kp;
    }
}

// Create delegation certificate
std::optional<Certificate> create_certificate(
    std::chrono::system_clock::time_point min_time,
    std::chrono::system_clock::time_point max_time,
    const std::array<uint8_t, ED25519_PUBLIC_KEY_SIZE>& online_public_key,
    const std::array<uint8_t, 64>& online_private_key,
    const std::array<uint8_t, 64>& root_private_key
) {
    // Validate time range
    auto time_validation = validation::validate_time_range(min_time, max_time);
    if (!time_validation) {
        LOG(ERROR) << "Invalid time range: " << time_validation.error_message;
        return std::nullopt;
    }

    Certificate cert;
    cert.online_public_key = online_public_key;
    cert.online_private_key = online_private_key;

    // Calculate SRV hash for this root key
    std::array<uint8_t, ED25519_PUBLIC_KEY_SIZE> root_public_key;
    std::memcpy(root_public_key.data(), root_private_key.data() + 32, 32);

    std::vector<uint8_t> srv_input;
    srv_input.push_back(0xff);
    srv_input.insert(srv_input.end(), root_public_key.begin(), root_public_key.end());
    auto srv_hash_full = crypto::sha512(srv_input);
    cert.srv_hash = std::vector<uint8_t>(srv_hash_full.begin(), srv_hash_full.begin() + 32);

    // Create DELE message
    Message dele;
    dele[tags::PUBK] = std::vector<uint8_t>(online_public_key.begin(), online_public_key.end());

    // IETF version (MJD format timestamps)
    {
        auto min_seconds = std::chrono::duration_cast<std::chrono::seconds>(
            min_time.time_since_epoch()).count();
        auto max_seconds = std::chrono::duration_cast<std::chrono::seconds>(
            max_time.time_since_epoch()).count();

        // Convert to MJD format
        const uint64_t UNIX_EPOCH_MJD = 40587;

        // MINT
        uint64_t min_days_since_unix = static_cast<uint64_t>(min_seconds / 86400);
        uint64_t min_mjd = UNIX_EPOCH_MJD + min_days_since_unix;
        uint64_t min_secs_of_day = static_cast<uint64_t>(min_seconds % 86400);
        uint64_t min_usec_of_day = min_secs_of_day * 1000000;
        uint64_t mint_mjd = (min_mjd << 40) | (min_usec_of_day & 0xFFFFFFFFFF);

        // MAXT
        uint64_t max_days_since_unix = static_cast<uint64_t>(max_seconds / 86400);
        uint64_t max_mjd = UNIX_EPOCH_MJD + max_days_since_unix;
        uint64_t max_secs_of_day = static_cast<uint64_t>(max_seconds % 86400);
        uint64_t max_usec_of_day = max_secs_of_day * 1000000;
        uint64_t maxt_mjd = (max_mjd << 40) | (max_usec_of_day & 0xFFFFFFFFFF);

        std::vector<uint8_t> mint_bytes(8);
        std::vector<uint8_t> maxt_bytes(8);
        write_le64(mint_bytes.data(), mint_mjd);
        write_le64(maxt_bytes.data(), maxt_mjd);

        dele[tags::MINT] = mint_bytes;
        dele[tags::MAXT] = maxt_bytes;

        auto dele_bytes = encode(dele);

        // Sign delegation
        std::vector<uint8_t> to_sign(CERTIFICATE_CONTEXT, CERTIFICATE_CONTEXT + CERTIFICATE_CONTEXT_LEN);
        to_sign.insert(to_sign.end(), dele_bytes.begin(), dele_bytes.end());

        std::array<uint8_t, 64> signature;
        ed25519_sign(signature, to_sign.data(), to_sign.size(), root_private_key.data());

        Message cert_msg;
        cert_msg[tags::DELE] = dele_bytes;
        cert_msg[tags::SIG] = std::vector<uint8_t>(signature.begin(), signature.end());

        cert.bytes_ietf = encode(cert_msg);
    }

    // Google version (microseconds since epoch)
    {
        auto min_micros = std::chrono::duration_cast<std::chrono::microseconds>(
            min_time.time_since_epoch()).count();
        auto max_micros = std::chrono::duration_cast<std::chrono::microseconds>(
            max_time.time_since_epoch()).count();

        Message dele_google;
        dele_google[tags::PUBK] = std::vector<uint8_t>(online_public_key.begin(), online_public_key.end());

        std::vector<uint8_t> mint_bytes(8);
        std::vector<uint8_t> maxt_bytes(8);
        write_le64(mint_bytes.data(), static_cast<uint64_t>(min_micros));
        write_le64(maxt_bytes.data(), static_cast<uint64_t>(max_micros));

        dele_google[tags::MINT] = mint_bytes;
        dele_google[tags::MAXT] = maxt_bytes;

        auto dele_bytes_google = encode(dele_google);

        // Sign delegation
        std::vector<uint8_t> to_sign(CERTIFICATE_CONTEXT, CERTIFICATE_CONTEXT + CERTIFICATE_CONTEXT_LEN);
        to_sign.insert(to_sign.end(), dele_bytes_google.begin(), dele_bytes_google.end());

        std::array<uint8_t, 64> signature;
        ed25519_sign(signature, to_sign.data(), to_sign.size(), root_private_key.data());

        Message cert_msg;
        cert_msg[tags::DELE] = dele_bytes_google;
        cert_msg[tags::SIG] = std::vector<uint8_t>(signature.begin(), signature.end());

        cert.bytes_google = encode(cert_msg);
    }

    return cert;
}

// Parse client request
std::optional<ParsedRequest> parse_request(const std::vector<uint8_t>& request_bytes) {
    // Validate request size
    auto size_validation = validation::validate_request_size(request_bytes.size());
    if (!size_validation) {
        LOG(WARNING) << "Invalid request size: " << size_validation.error_message;
        return std::nullopt;
    }

    auto framed = decode_framed(request_bytes);
    if (!framed) {
        LOG(WARNING) << "Failed to decode frame";
        return std::nullopt;
    }

    auto msg = decode(framed->data);
    if (!msg) {
        LOG(WARNING) << "Failed to decode message";
        return std::nullopt;
    }

    ParsedRequest req;

    // Get NONC
    auto nonc_it = msg->find(tags::NONC);
    if (nonc_it == msg->end()) {
        LOG(WARNING) << "Missing NONC tag";
        return std::nullopt;
    }
    req.nonce = nonc_it->second;

    // Get versions (IETF) or assume Google
    bool is_ietf = framed->is_ietf;
    if (is_ietf) {
        auto ver_it = msg->find(tags::VER);
        if (ver_it != msg->end() && ver_it->second.size() >= 4) {
            size_t num_versions = ver_it->second.size() / 4;
            for (size_t i = 0; i < num_versions; i++) {
                uint32_t ver_val = read_le32(ver_it->second.data() + i * 4);
                req.versions.push_back(static_cast<Version>(ver_val));
            }
        }

        // Default to Draft08 if no versions specified
        if (req.versions.empty()) {
            req.versions.push_back(Version::Draft08);
        }

        // Select response version (prefer Draft11, then Draft08, then Draft07)
        if (std::find(req.versions.begin(), req.versions.end(), Version::Draft11) != req.versions.end()) {
            req.response_version = Version::Draft11;
        } else if (std::find(req.versions.begin(), req.versions.end(), Version::Draft08) != req.versions.end()) {
            req.response_version = Version::Draft08;
        } else if (std::find(req.versions.begin(), req.versions.end(), Version::Draft07) != req.versions.end()) {
            req.response_version = Version::Draft07;
        } else {
            LOG(WARNING) << "No supported version in request";
            return std::nullopt;
        }

        // Get SRV tag if present
        auto srv_it = msg->find(tags::SRV);
        if (srv_it != msg->end()) {
            req.srv = srv_it->second;
        }
    } else {
        req.versions.push_back(Version::Google);
        req.response_version = Version::Google;
    }

    return req;
}

// Create responses for batch of requests
std::vector<std::vector<uint8_t>> create_replies(
    const std::vector<ParsedRequest>& requests,
    std::chrono::system_clock::time_point midpoint,
    std::chrono::seconds radius,
    const Certificate& cert
) {
    // Validate batch size
    auto batch_validation = validation::validate_batch_size(requests.size());
    if (!batch_validation) {
        LOG(WARNING) << "Invalid batch size: " << batch_validation.error_message;
        return {};
    }

    // All requests must use same version
    Version ver = requests[0].response_version;
    bool version_ietf = (ver != Version::Google);
    size_t nonce_size = version_ietf ? 32 : 64;

    // Verify all requests match version
    for (const auto& req : requests) {
        if (req.response_version != ver) {
            LOG(ERROR) << "Mixed versions in batch";
            return {};
        }
    }

    // Build Merkle tree from nonces
    std::vector<std::vector<uint8_t>> nonces;
    for (const auto& req : requests) {
        nonces.push_back(req.nonce);
    }

    crypto::MerkleTree tree(nonce_size, nonces);
    auto root = tree.root();

    // Create signed response
    uint64_t midpoint_val;
    uint32_t radius_val;

    if (version_ietf) {
        // IETF Roughtime uses Modified Julian Date (MJD) format
        // Top 24 bits: MJD (days since Nov 17, 1858)
        // Bottom 40 bits: Microseconds since midnight
        auto unix_seconds = std::chrono::duration_cast<std::chrono::seconds>(
            midpoint.time_since_epoch()).count();

        // Unix epoch (Jan 1, 1970) is MJD 40587
        const uint64_t UNIX_EPOCH_MJD = 40587;
        uint64_t days_since_unix = static_cast<uint64_t>(unix_seconds / 86400);
        uint64_t mjd = UNIX_EPOCH_MJD + days_since_unix;

        // Microseconds since midnight
        uint64_t secs_of_day = static_cast<uint64_t>(unix_seconds % 86400);
        uint64_t usec_of_day = secs_of_day * 1000000;

        // Pack into MJD timestamp
        midpoint_val = (mjd << 40) | (usec_of_day & 0xFFFFFFFFFF);
        radius_val = static_cast<uint32_t>(radius.count());
    } else {
        midpoint_val = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
            midpoint.time_since_epoch()).count());
        radius_val = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::microseconds>(radius).count());
    }

    Message srep;
    std::vector<uint8_t> midp_bytes(8);
    std::vector<uint8_t> radi_bytes(4);
    write_le64(midp_bytes.data(), midpoint_val);
    write_le32(radi_bytes.data(), radius_val);

    srep[tags::MIDP] = midp_bytes;
    srep[tags::RADI] = radi_bytes;
    srep[tags::ROOT] = root;

    auto srep_bytes = encode(srep);

    // Sign the response
    std::vector<uint8_t> to_sign(SIGNED_RESPONSE_CONTEXT, SIGNED_RESPONSE_CONTEXT + SIGNED_RESPONSE_CONTEXT_LEN);
    to_sign.insert(to_sign.end(), srep_bytes.begin(), srep_bytes.end());

    std::array<uint8_t, 64> signature;
    ed25519_sign(signature, to_sign.data(), to_sign.size(), cert.online_private_key.data());

    // Build reply template
    Message reply_template;
    reply_template[tags::SREP] = srep_bytes;
    reply_template[tags::SIG] = std::vector<uint8_t>(signature.begin(), signature.end());
    reply_template[tags::CERT] = version_ietf ? cert.bytes_ietf : cert.bytes_google;

    if (version_ietf) {
        std::vector<uint8_t> ver_bytes(4);
        write_le32(ver_bytes.data(), static_cast<uint32_t>(ver));
        reply_template[tags::VER] = ver_bytes;
    }

    // Create individual replies with Merkle paths
    std::vector<std::vector<uint8_t>> replies;
    replies.reserve(requests.size());

    for (size_t i = 0; i < requests.size(); i++) {
        Message reply = reply_template;

        // Add index
        std::vector<uint8_t> indx_bytes(4);
        write_le32(indx_bytes.data(), static_cast<uint32_t>(i));
        reply[tags::INDX] = indx_bytes;

        // Add nonce
        reply[tags::NONC] = requests[i].nonce;

        // Add Merkle path
        auto path = tree.path(i);
        std::vector<uint8_t> path_bytes;
        for (const auto& step : path) {
            path_bytes.insert(path_bytes.end(), step.begin(), step.end());
        }
        reply[tags::PATH] = path_bytes;

        auto reply_bytes = encode(reply);
        auto framed_reply = encode_framed(version_ietf, reply_bytes);

        replies.push_back(framed_reply);
    }

    return replies;
}

// Server implementation
class Server::Impl {
public:
    Impl(const ServerConfig& config)
        : config_(config)
        , rate_limiter_(config.rate_limit)
        , running_(false)
        , socket_fd_(-1)
    {
        // Validate server configuration
        auto config_validation = validation::validate_server_config(config);
        if (!config_validation) {
            throw std::invalid_argument("Invalid server configuration: " + config_validation.error_message);
        }

        // Generate online keypair
        auto online_kp = keygen::generate_keypair();

        // Create certificate
        auto now = std::chrono::system_clock::now();
        auto min_time = now - std::chrono::hours(24);
        auto max_time = now + config_.cert_validity;

        auto cert_opt = create_certificate(min_time, max_time, online_kp.public_key, online_kp.private_key, config_.root_private_key);
        if (!cert_opt) {
            throw std::runtime_error("Failed to create certificate");
        }
        cert_ = *cert_opt;

    }

    ~Impl() {
        stop();
    }

    void run() {
        // Create UDP socket
        socket_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
        if (socket_fd_ < 0) {
            throw std::runtime_error("Failed to create socket");
        }

        // Enable SO_REUSEADDR to allow quick restart
        int reuse = 1;
        if (setsockopt(socket_fd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
            close(socket_fd_);
            throw std::runtime_error("Failed to set SO_REUSEADDR");
        }

        // Set receive timeout to allow checking running_ flag periodically
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 200000; // 200ms timeout
        if (setsockopt(socket_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            close(socket_fd_);
            throw std::runtime_error("Failed to set SO_RCVTIMEO");
        }

        // Bind to address
        struct sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port);
        if (inet_pton(AF_INET, config_.address.c_str(), &addr.sin_addr) <= 0) {
            throw std::runtime_error("Invalid address: " + config_.address);
        }

        if (bind(socket_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
            close(socket_fd_);
            throw std::runtime_error("Failed to bind to " + config_.address + ":" + std::to_string(config_.port));
        }

        running_ = true;

        std::vector<uint8_t> buffer(2048);

        while (running_) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);

            ssize_t recv_len = recvfrom(socket_fd_, buffer.data(), buffer.size(), 0,
                                       reinterpret_cast<struct sockaddr*>(&client_addr), &client_len);

            if (recv_len < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // Timeout - just check running_ flag and continue
                    continue;
                }
                if (!running_) {
                    // Server is shutting down, exit cleanly
                    break;
                }
                LOG(ERROR) << "recvfrom failed: " << std::strerror(errno);
                continue;
            }

            std::vector<uint8_t> request(buffer.begin(), buffer.begin() + recv_len);

            // Handle request
            handle_request(request, client_addr);
        }
    }

    void stop() {
        running_ = false;
        if (socket_fd_ >= 0) {
            close(socket_fd_);
            socket_fd_ = -1;
        }
    }

private:
    void handle_request(const std::vector<uint8_t>& request_bytes, const struct sockaddr_in& client_addr) {
        // Convert client address to string for rate limiting
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

        // Check rate limit
        if (config_.rate_limit.enabled && !rate_limiter_.allow_request(client_ip)) {
            LOG(WARNING) << "Rate limit exceeded for " << client_ip;
            return;  // Drop request
        }

        auto req = parse_request(request_bytes);
        if (!req) {
            LOG(WARNING) << "Failed to parse request from " << client_ip;
            return;
        }

        // Create reply
        auto now = std::chrono::system_clock::now();
        auto replies = create_replies({*req}, now, config_.radius, cert_);

        if (replies.empty()) {
            LOG(ERROR) << "Failed to create reply";
            return;
        }

        // Send response
        ssize_t sent = sendto(socket_fd_, replies[0].data(), replies[0].size(), 0,
                             reinterpret_cast<const struct sockaddr*>(&client_addr), sizeof(client_addr));

        if (sent < 0) {
            LOG(ERROR) << "sendto failed: " << std::strerror(errno);
        }
    }

    ServerConfig config_;
    Certificate cert_;
    RateLimiter rate_limiter_;
    std::atomic<bool> running_;
    int socket_fd_;
};

Server::Server(const ServerConfig& config) : impl_(std::make_unique<Impl>(config)) {}

Server::~Server() = default;

void Server::run() {
    impl_->run();
}

void Server::stop() {
    impl_->stop();
}

} // namespace server
} // namespace roughtime

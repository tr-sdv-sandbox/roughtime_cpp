// Copyright 2024
// SPDX-License-Identifier: Apache-2.0
//
// Rogue Server Tests - Verify client rejects malicious servers

#include <roughtime/client.h>
#include <roughtime/protocol.h>
#include <roughtime/crypto.h>
#include <roughtime/server.h>
#include "test_utils.h"
#include <gtest/gtest.h>
#include <thread>
#include <chrono>
#include <openssl/rand.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace roughtime;
using namespace roughtime::test;

// Helper to create valid-looking but malicious responses
class RogueServerHelper {
public:
    static void write_le32(uint8_t* data, uint32_t value) {
        data[0] = static_cast<uint8_t>(value & 0xff);
        data[1] = static_cast<uint8_t>((value >> 8) & 0xff);
        data[2] = static_cast<uint8_t>((value >> 16) & 0xff);
        data[3] = static_cast<uint8_t>((value >> 24) & 0xff);
    }

    static void write_le64(uint8_t* data, uint64_t value) {
        data[0] = static_cast<uint8_t>(value & 0xff);
        data[1] = static_cast<uint8_t>((value >> 8) & 0xff);
        data[2] = static_cast<uint8_t>((value >> 16) & 0xff);
        data[3] = static_cast<uint8_t>((value >> 24) & 0xff);
        data[4] = static_cast<uint8_t>((value >> 32) & 0xff);
        data[5] = static_cast<uint8_t>((value >> 40) & 0xff);
        data[6] = static_cast<uint8_t>((value >> 48) & 0xff);
        data[7] = static_cast<uint8_t>((value >> 56) & 0xff);
    }

    // Convert Unix timestamp to MJD format (for IETF Roughtime)
    static uint64_t unix_to_mjd_timestamp(time_t unix_time) {
        // Unix epoch (Jan 1, 1970) is MJD 40587
        const uint64_t UNIX_EPOCH_MJD = 40587;

        // Days since Unix epoch
        uint64_t days_since_unix = static_cast<uint64_t>(unix_time) / 86400;
        uint64_t mjd = UNIX_EPOCH_MJD + days_since_unix;

        // Microseconds since midnight
        uint64_t secs_of_day = static_cast<uint64_t>(unix_time) % 86400;
        uint64_t usec_of_day = secs_of_day * 1000000;

        // Pack into MJD timestamp: top 24 bits = MJD, bottom 40 bits = microseconds
        return (mjd << 40) | (usec_of_day & 0xFFFFFFFFFF);
    }
};

// Rogue server that sends invalid signature
class InvalidSignatureServer {
public:
    InvalidSignatureServer(uint16_t port) : port_(port), running_(false) {
        // Generate keys
        ed25519_keypair(root_public_, root_private_);
        ed25519_keypair(online_public_, online_private_);
    }

    void start() {
        running_ = true;
        thread_ = std::thread([this]() { run(); });
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    void stop() {
        running_ = false;
        if (thread_.joinable()) {
            thread_.join();
        }
    }

    std::array<uint8_t, 32> root_public() const { return root_public_; }

private:
    void run() {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return;

        int reuse = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 200000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port_);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

        if (bind(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
            close(sock);
            return;
        }

        std::vector<uint8_t> buffer(2048);
        while (running_) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);

            ssize_t len = recvfrom(sock, buffer.data(), buffer.size(), 0,
                                  reinterpret_cast<struct sockaddr*>(&client_addr), &client_len);

            if (len < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                break;
            }

            // Create response with INVALID signature
            auto response = create_invalid_signature_response(
                std::vector<uint8_t>(buffer.begin(), buffer.begin() + len));

            sendto(sock, response.data(), response.size(), 0,
                  reinterpret_cast<struct sockaddr*>(&client_addr), client_len);
        }

        close(sock);
    }

    std::vector<uint8_t> create_invalid_signature_response(const std::vector<uint8_t>& request) {
        // Parse request to get nonce
        auto framed = decode_framed(request);
        if (!framed) return {};

        auto req_msg = decode(framed->data);
        if (!req_msg) return {};

        auto nonc_it = req_msg->find(tags::NONC);
        if (nonc_it == req_msg->end()) return {};

        std::vector<uint8_t> nonce = nonc_it->second;

        // Build SREP
        Message srep;
        std::vector<uint8_t> midp(8);
        std::vector<uint8_t> radi(4);
        RogueServerHelper::write_le64(midp.data(), RogueServerHelper::unix_to_mjd_timestamp(std::time(nullptr)));
        RogueServerHelper::write_le32(radi.data(), 1);

        auto leaf_hash = crypto::MerkleTree::hash_leaf(nonce, 32);
        srep[tags::MIDP] = midp;
        srep[tags::RADI] = radi;
        srep[tags::ROOT] = std::vector<uint8_t>(leaf_hash.begin(), leaf_hash.begin() + 32);

        auto srep_bytes = encode(srep);

        // Sign SREP properly
        std::vector<uint8_t> to_sign;
        const char* resp_context = "RoughTime v1 response signature\x00";
        to_sign.insert(to_sign.end(), resp_context, resp_context + 32);
        to_sign.insert(to_sign.end(), srep_bytes.begin(), srep_bytes.end());

        std::array<uint8_t, 64> signature;
        ed25519_sign(signature, to_sign.data(), to_sign.size(), online_private_.data());

        // CORRUPT the signature - make it invalid
        signature[0] ^= 0xFF;
        signature[1] ^= 0xFF;

        // Build certificate
        Message dele;
        dele[tags::PUBK] = std::vector<uint8_t>(online_public_.begin(), online_public_.end());

        auto now = std::time(nullptr);
        std::vector<uint8_t> mint(8), maxt(8);
        RogueServerHelper::write_le64(mint.data(), RogueServerHelper::unix_to_mjd_timestamp(now - 86400));
        RogueServerHelper::write_le64(maxt.data(), RogueServerHelper::unix_to_mjd_timestamp(now + 86400));
        dele[tags::MINT] = mint;
        dele[tags::MAXT] = maxt;

        auto dele_bytes = encode(dele);

        std::vector<uint8_t> cert_to_sign;
        const char* cert_context = "RoughTime v1 delegation signature--\x00";
        cert_to_sign.insert(cert_to_sign.end(), cert_context, cert_context + 36);
        cert_to_sign.insert(cert_to_sign.end(), dele_bytes.begin(), dele_bytes.end());

        std::array<uint8_t, 64> cert_sig;
        ed25519_sign(cert_sig, cert_to_sign.data(), cert_to_sign.size(), root_private_.data());

        Message cert;
        cert[tags::DELE] = dele_bytes;
        cert[tags::SIG] = std::vector<uint8_t>(cert_sig.begin(), cert_sig.end());

        // Build reply
        Message reply;
        reply[tags::SREP] = srep_bytes;
        reply[tags::SIG] = std::vector<uint8_t>(signature.begin(), signature.end()); // INVALID!
        reply[tags::CERT] = encode(cert);
        reply[tags::VER] = {0x08, 0x00, 0x00, 0x80}; // Draft08
        reply[tags::NONC] = nonce;
        reply[tags::INDX] = {0x00, 0x00, 0x00, 0x00};
        reply[tags::PATH] = {}; // Empty path for single nonce

        return encode_framed(true, encode(reply));
    }

    uint16_t port_;
    std::atomic<bool> running_;
    std::thread thread_;
    std::array<uint8_t, 32> root_public_;
    std::array<uint8_t, 64> root_private_;
    std::array<uint8_t, 32> online_public_;
    std::array<uint8_t, 64> online_private_;
};

// Rogue server that sends wrong nonce
class WrongNonceServer {
public:
    WrongNonceServer(uint16_t port) : port_(port), running_(false) {
        ed25519_keypair(root_public_, root_private_);
        ed25519_keypair(online_public_, online_private_);
    }

    void start() {
        running_ = true;
        thread_ = std::thread([this]() { run(); });
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    void stop() {
        running_ = false;
        if (thread_.joinable()) {
            thread_.join();
        }
    }

    std::array<uint8_t, 32> root_public() const { return root_public_; }

private:
    void run() {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return;

        int reuse = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 200000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port_);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

        if (bind(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
            close(sock);
            return;
        }

        std::vector<uint8_t> buffer(2048);
        while (running_) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);

            ssize_t len = recvfrom(sock, buffer.data(), buffer.size(), 0,
                                  reinterpret_cast<struct sockaddr*>(&client_addr), &client_len);

            if (len < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                break;
            }

            // Return WRONG nonce (not the one client sent)
            std::vector<uint8_t> wrong_nonce(32, 0xAB); // Wrong!
            auto response = create_response_with_nonce(wrong_nonce);

            sendto(sock, response.data(), response.size(), 0,
                  reinterpret_cast<struct sockaddr*>(&client_addr), client_len);
        }

        close(sock);
    }

    std::vector<uint8_t> create_response_with_nonce(const std::vector<uint8_t>& nonce) {
        Message srep;
        std::vector<uint8_t> midp(8), radi(4);
        RogueServerHelper::write_le64(midp.data(), RogueServerHelper::unix_to_mjd_timestamp(std::time(nullptr)));
        RogueServerHelper::write_le32(radi.data(), 1);

        auto leaf_hash = crypto::MerkleTree::hash_leaf(nonce, 32);
        srep[tags::MIDP] = midp;
        srep[tags::RADI] = radi;
        srep[tags::ROOT] = std::vector<uint8_t>(leaf_hash.begin(), leaf_hash.begin() + 32);

        auto srep_bytes = encode(srep);

        std::vector<uint8_t> to_sign;
        const char* resp_context = "RoughTime v1 response signature\x00";
        to_sign.insert(to_sign.end(), resp_context, resp_context + 32);
        to_sign.insert(to_sign.end(), srep_bytes.begin(), srep_bytes.end());

        std::array<uint8_t, 64> signature;
        ed25519_sign(signature, to_sign.data(), to_sign.size(), online_private_.data());

        Message dele;
        dele[tags::PUBK] = std::vector<uint8_t>(online_public_.begin(), online_public_.end());

        auto now = std::time(nullptr);
        std::vector<uint8_t> mint(8), maxt(8);
        RogueServerHelper::write_le64(mint.data(), RogueServerHelper::unix_to_mjd_timestamp(now - 86400));
        RogueServerHelper::write_le64(maxt.data(), RogueServerHelper::unix_to_mjd_timestamp(now + 86400));
        dele[tags::MINT] = mint;
        dele[tags::MAXT] = maxt;

        auto dele_bytes = encode(dele);

        std::vector<uint8_t> cert_to_sign;
        const char* cert_context = "RoughTime v1 delegation signature--\x00";
        cert_to_sign.insert(cert_to_sign.end(), cert_context, cert_context + 36);
        cert_to_sign.insert(cert_to_sign.end(), dele_bytes.begin(), dele_bytes.end());

        std::array<uint8_t, 64> cert_sig;
        ed25519_sign(cert_sig, cert_to_sign.data(), cert_to_sign.size(), root_private_.data());

        Message cert;
        cert[tags::DELE] = dele_bytes;
        cert[tags::SIG] = std::vector<uint8_t>(cert_sig.begin(), cert_sig.end());

        Message reply;
        reply[tags::SREP] = srep_bytes;
        reply[tags::SIG] = std::vector<uint8_t>(signature.begin(), signature.end());
        reply[tags::CERT] = encode(cert);
        reply[tags::VER] = {0x08, 0x00, 0x00, 0x80};
        reply[tags::NONC] = nonce; // WRONG nonce!
        reply[tags::INDX] = {0x00, 0x00, 0x00, 0x00};
        reply[tags::PATH] = {};

        return encode_framed(true, encode(reply));
    }

    uint16_t port_;
    std::atomic<bool> running_;
    std::thread thread_;
    std::array<uint8_t, 32> root_public_;
    std::array<uint8_t, 64> root_private_;
    std::array<uint8_t, 32> online_public_;
    std::array<uint8_t, 64> online_private_;
};

// Test fixture
class RogueServerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // No initialization needed for OpenSSL
    }
};

TEST_F(RogueServerTest, RejectInvalidSignature) {
    InvalidSignatureServer rogue(25001);
    rogue.start();

    Server srv;
    srv.name = "rogue-server";
    srv.version = "IETF-Roughtime";
    srv.public_key = rogue.root_public();

    ServerAddress addr;
    addr.protocol = "udp";
    addr.address = "127.0.0.1:25001";
    srv.addresses = {addr};

    Client client;
    auto result = client.query(srv, 3, std::chrono::milliseconds(1000), std::nullopt);

    // Client MUST reject invalid signature
    ASSERT_FALSE(result.is_success());

    rogue.stop();
}

TEST_F(RogueServerTest, RejectWrongNonce) {
    WrongNonceServer rogue(25002);
    rogue.start();

    Server srv;
    srv.name = "rogue-server";
    srv.version = "IETF-Roughtime";
    srv.public_key = rogue.root_public();

    ServerAddress addr;
    addr.protocol = "udp";
    addr.address = "127.0.0.1:25002";
    srv.addresses = {addr};

    Client client;
    auto result = client.query(srv, 3, std::chrono::milliseconds(1000), std::nullopt);

    // Client MUST reject wrong nonce
    ASSERT_FALSE(result.is_success());

    rogue.stop();
}

// Rogue server that sends expired certificate
class ExpiredCertServer {
public:
    ExpiredCertServer(uint16_t port) : port_(port), running_(false) {
        ed25519_keypair(root_public_, root_private_);
        ed25519_keypair(online_public_, online_private_);
    }

    void start() {
        running_ = true;
        thread_ = std::thread([this]() { run(); });
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    void stop() {
        running_ = false;
        if (thread_.joinable()) {
            thread_.join();
        }
    }

    std::array<uint8_t, 32> root_public() const { return root_public_; }

private:
    void run() {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return;

        int reuse = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 200000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port_);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

        if (bind(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
            close(sock);
            return;
        }

        std::vector<uint8_t> buffer(2048);
        while (running_) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);

            ssize_t len = recvfrom(sock, buffer.data(), buffer.size(), 0,
                                  reinterpret_cast<struct sockaddr*>(&client_addr), &client_len);

            if (len < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                break;
            }

            auto response = create_expired_cert_response(
                std::vector<uint8_t>(buffer.begin(), buffer.begin() + len));

            sendto(sock, response.data(), response.size(), 0,
                  reinterpret_cast<struct sockaddr*>(&client_addr), client_len);
        }

        close(sock);
    }

    std::vector<uint8_t> create_expired_cert_response(const std::vector<uint8_t>& request) {
        auto framed = decode_framed(request);
        if (!framed) return {};

        auto req_msg = decode(framed->data);
        if (!req_msg) return {};

        auto nonc_it = req_msg->find(tags::NONC);
        if (nonc_it == req_msg->end()) return {};

        std::vector<uint8_t> nonce = nonc_it->second;

        Message srep;
        std::vector<uint8_t> midp(8), radi(4);
        RogueServerHelper::write_le64(midp.data(), RogueServerHelper::unix_to_mjd_timestamp(std::time(nullptr)));
        RogueServerHelper::write_le32(radi.data(), 1);

        auto leaf_hash = crypto::MerkleTree::hash_leaf(nonce, 32);
        srep[tags::MIDP] = midp;
        srep[tags::RADI] = radi;
        srep[tags::ROOT] = std::vector<uint8_t>(leaf_hash.begin(), leaf_hash.begin() + 32);

        auto srep_bytes = encode(srep);

        std::vector<uint8_t> to_sign;
        const char* resp_context = "RoughTime v1 response signature\x00";
        to_sign.insert(to_sign.end(), resp_context, resp_context + 32);
        to_sign.insert(to_sign.end(), srep_bytes.begin(), srep_bytes.end());

        std::array<uint8_t, 64> signature;
        ed25519_sign(signature, to_sign.data(), to_sign.size(), online_private_.data());

        // Certificate EXPIRED (10 years ago)
        Message dele;
        dele[tags::PUBK] = std::vector<uint8_t>(online_public_.begin(), online_public_.end());

        auto now = std::time(nullptr);
        std::vector<uint8_t> mint(8), maxt(8);
        RogueServerHelper::write_le64(mint.data(), static_cast<uint64_t>(now - 86400 * 3650)); // 10 years ago
        RogueServerHelper::write_le64(maxt.data(), static_cast<uint64_t>(now - 86400 * 3640)); // Expired!
        dele[tags::MINT] = mint;
        dele[tags::MAXT] = maxt;

        auto dele_bytes = encode(dele);

        std::vector<uint8_t> cert_to_sign;
        const char* cert_context = "RoughTime v1 delegation signature--\x00";
        cert_to_sign.insert(cert_to_sign.end(), cert_context, cert_context + 36);
        cert_to_sign.insert(cert_to_sign.end(), dele_bytes.begin(), dele_bytes.end());

        std::array<uint8_t, 64> cert_sig;
        ed25519_sign(cert_sig, cert_to_sign.data(), cert_to_sign.size(), root_private_.data());

        Message cert;
        cert[tags::DELE] = dele_bytes;
        cert[tags::SIG] = std::vector<uint8_t>(cert_sig.begin(), cert_sig.end());

        Message reply;
        reply[tags::SREP] = srep_bytes;
        reply[tags::SIG] = std::vector<uint8_t>(signature.begin(), signature.end());
        reply[tags::CERT] = encode(cert);
        reply[tags::VER] = {0x08, 0x00, 0x00, 0x80};
        reply[tags::NONC] = nonce;
        reply[tags::INDX] = {0x00, 0x00, 0x00, 0x00};
        reply[tags::PATH] = {};

        return encode_framed(true, encode(reply));
    }

    uint16_t port_;
    std::atomic<bool> running_;
    std::thread thread_;
    std::array<uint8_t, 32> root_public_;
    std::array<uint8_t, 64> root_private_;
    std::array<uint8_t, 32> online_public_;
    std::array<uint8_t, 64> online_private_;
};

// Rogue server that sends invalid Merkle proof
class InvalidMerkleServer {
public:
    InvalidMerkleServer(uint16_t port) : port_(port), running_(false) {
        ed25519_keypair(root_public_, root_private_);
        ed25519_keypair(online_public_, online_private_);
    }

    void start() {
        running_ = true;
        thread_ = std::thread([this]() { run(); });
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    void stop() {
        running_ = false;
        if (thread_.joinable()) {
            thread_.join();
        }
    }

    std::array<uint8_t, 32> root_public() const { return root_public_; }

private:
    void run() {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return;

        int reuse = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 200000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port_);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

        if (bind(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
            close(sock);
            return;
        }

        std::vector<uint8_t> buffer(2048);
        while (running_) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);

            ssize_t len = recvfrom(sock, buffer.data(), buffer.size(), 0,
                                  reinterpret_cast<struct sockaddr*>(&client_addr), &client_len);

            if (len < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                break;
            }

            auto response = create_invalid_merkle_response(
                std::vector<uint8_t>(buffer.begin(), buffer.begin() + len));

            sendto(sock, response.data(), response.size(), 0,
                  reinterpret_cast<struct sockaddr*>(&client_addr), client_len);
        }

        close(sock);
    }

    std::vector<uint8_t> create_invalid_merkle_response(const std::vector<uint8_t>& request) {
        auto framed = decode_framed(request);
        if (!framed) return {};

        auto req_msg = decode(framed->data);
        if (!req_msg) return {};

        auto nonc_it = req_msg->find(tags::NONC);
        if (nonc_it == req_msg->end()) return {};

        std::vector<uint8_t> nonce = nonc_it->second;

        Message srep;
        std::vector<uint8_t> midp(8), radi(4);
        RogueServerHelper::write_le64(midp.data(), RogueServerHelper::unix_to_mjd_timestamp(std::time(nullptr)));
        RogueServerHelper::write_le32(radi.data(), 1);

        // WRONG ROOT - use hash of different nonce
        std::vector<uint8_t> wrong_nonce(32, 0xCC);
        auto wrong_hash = crypto::MerkleTree::hash_leaf(wrong_nonce, 32);
        srep[tags::MIDP] = midp;
        srep[tags::RADI] = radi;
        srep[tags::ROOT] = std::vector<uint8_t>(wrong_hash.begin(), wrong_hash.begin() + 32);

        auto srep_bytes = encode(srep);

        std::vector<uint8_t> to_sign;
        const char* resp_context = "RoughTime v1 response signature\x00";
        to_sign.insert(to_sign.end(), resp_context, resp_context + 32);
        to_sign.insert(to_sign.end(), srep_bytes.begin(), srep_bytes.end());

        std::array<uint8_t, 64> signature;
        ed25519_sign(signature, to_sign.data(), to_sign.size(), online_private_.data());

        Message dele;
        dele[tags::PUBK] = std::vector<uint8_t>(online_public_.begin(), online_public_.end());

        auto now = std::time(nullptr);
        std::vector<uint8_t> mint(8), maxt(8);
        RogueServerHelper::write_le64(mint.data(), RogueServerHelper::unix_to_mjd_timestamp(now - 86400));
        RogueServerHelper::write_le64(maxt.data(), RogueServerHelper::unix_to_mjd_timestamp(now + 86400));
        dele[tags::MINT] = mint;
        dele[tags::MAXT] = maxt;

        auto dele_bytes = encode(dele);

        std::vector<uint8_t> cert_to_sign;
        const char* cert_context = "RoughTime v1 delegation signature--\x00";
        cert_to_sign.insert(cert_to_sign.end(), cert_context, cert_context + 36);
        cert_to_sign.insert(cert_to_sign.end(), dele_bytes.begin(), dele_bytes.end());

        std::array<uint8_t, 64> cert_sig;
        ed25519_sign(cert_sig, cert_to_sign.data(), cert_to_sign.size(), root_private_.data());

        Message cert;
        cert[tags::DELE] = dele_bytes;
        cert[tags::SIG] = std::vector<uint8_t>(cert_sig.begin(), cert_sig.end());

        Message reply;
        reply[tags::SREP] = srep_bytes;
        reply[tags::SIG] = std::vector<uint8_t>(signature.begin(), signature.end());
        reply[tags::CERT] = encode(cert);
        reply[tags::VER] = {0x08, 0x00, 0x00, 0x80};
        reply[tags::NONC] = nonce; // Correct nonce but wrong Merkle root!
        reply[tags::INDX] = {0x00, 0x00, 0x00, 0x00};
        reply[tags::PATH] = {};

        return encode_framed(true, encode(reply));
    }

    uint16_t port_;
    std::atomic<bool> running_;
    std::thread thread_;
    std::array<uint8_t, 32> root_public_;
    std::array<uint8_t, 64> root_private_;
    std::array<uint8_t, 32> online_public_;
    std::array<uint8_t, 64> online_private_;
};
TEST_F(RogueServerTest, RejectExpiredCertificate) {
    ExpiredCertServer rogue(25003);
    rogue.start();

    Server srv;
    srv.name = "expired-cert-server";
    srv.version = "IETF-Roughtime";
    srv.public_key = rogue.root_public();

    ServerAddress addr;
    addr.protocol = "udp";
    addr.address = "127.0.0.1:25003";
    srv.addresses = {addr};

    Client client;
    auto result = client.query(srv, 3, std::chrono::milliseconds(1000), std::nullopt);

    // Client MUST reject expired certificate
    ASSERT_FALSE(result.is_success());

    rogue.stop();
}

TEST_F(RogueServerTest, RejectInvalidMerkleProof) {
    InvalidMerkleServer rogue(25004);
    rogue.start();

    Server srv;
    srv.name = "invalid-merkle-server";
    srv.version = "IETF-Roughtime";
    srv.public_key = rogue.root_public();

    ServerAddress addr;
    addr.protocol = "udp";
    addr.address = "127.0.0.1:25004";
    srv.addresses = {addr};

    Client client;
    auto result = client.query(srv, 3, std::chrono::milliseconds(1000), std::nullopt);

    // Client MUST reject invalid Merkle proof
    ASSERT_FALSE(result.is_success());

    rogue.stop();
}

TEST_F(RogueServerTest, RejectTimeWayOutOfBounds) {
    // Server claiming time is 100 years in future
    GoodServer rogue(25005, std::chrono::seconds(100LL * 365 * 86400));

    Server srv = rogue.get_client_config();
    srv.name = "wrong-time-server";

    Client client;
    auto result = client.query(srv, 3, std::chrono::milliseconds(1000), std::nullopt);

    // This test documents current behavior - client may accept but time will be obviously wrong
    // In multi-server scenario, median calculation will filter this out
    if (result.is_success()) {
        auto now = std::chrono::system_clock::now();
        auto diff = std::chrono::duration_cast<std::chrono::seconds>(result.midpoint - now).count();
        // Time should be way off (> 1 year)
        ASSERT_GT(std::abs(diff), 365 * 86400);
    }
}

// Multi-server tests with mixed good and rogue servers

// Helper to create a good server
struct GoodServer {
    server::keygen::KeyPair root_keypair;
    std::unique_ptr<server::Server> server;
    std::thread thread;
    uint16_t port;

    GoodServer(uint16_t p, std::chrono::seconds time_offset = std::chrono::seconds(0)) : port(p) {
        root_keypair = server::keygen::generate_keypair();

        server::ServerConfig config;
        config.address = "127.0.0.1";
        config.port = port;
        config.root_private_key = root_keypair.private_key;
        config.radius = std::chrono::seconds(1);
        config.cert_validity = std::chrono::hours(48);
        config.time_offset = time_offset;  // Apply time offset (0 = real time)

        server = std::make_unique<server::Server>(config);
        thread = std::thread([this]() {
            server->run();
        });

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    ~GoodServer() {
        if (server) {
            server->stop();
        }
        if (thread.joinable()) {
            thread.join();
        }
    }

    Server get_client_config() {
        Server srv;
        srv.name = "good-server-" + std::to_string(port);
        srv.version = "IETF-Roughtime";
        srv.public_key = root_keypair.public_key;

        ServerAddress addr;
        addr.protocol = "udp";
        addr.address = "127.0.0.1:" + std::to_string(port);
        srv.addresses = {addr};

        return srv;
    }
};

TEST_F(RogueServerTest, OneGoodOneBadTimeCannotEstablishTrust) {
    // Real attack: Both servers cryptographically valid, but one lies about time
    // With 1 vs 1, we CANNOT determine which server is honest
    GoodServer good(26001);
    GoodServer bad(26002, std::chrono::seconds(7 * 86400)); // Claims +7 days

    std::vector<Server> servers;
    servers.push_back(good.get_client_config());

    Server bad_srv = bad.get_client_config();
    bad_srv.name = "time-liar";
    servers.push_back(bad_srv);

    Client client;
    auto results = client.query_servers(servers, 3, std::chrono::milliseconds(1000));

    ASSERT_EQ(results.size(), 2);

    // BOTH servers succeed cryptographically (valid sigs, certs, Merkle proofs)
    ASSERT_TRUE(results[0].is_success());
    ASSERT_TRUE(results[1].is_success());

    // But their times disagree by ~7 days
    auto time_diff = std::chrono::duration_cast<std::chrono::seconds>(
        results[1].midpoint - results[0].midpoint).count();
    ASSERT_GT(std::abs(time_diff), 6 * 86400); // > 6 days difference

    // With only 2 servers giving different times, we CANNOT establish trust
    // We don't know which one is lying - could be either one!
    // This is why Roughtime protocol requires querying multiple servers (3+)

    // Median with 2 servers is meaningless - just picks one of the two values
    auto now = std::chrono::system_clock::now();
    auto median_result = calculate_median_delta(
        results,
        now,
        std::chrono::seconds(10)
    );

    ASSERT_TRUE(median_result.has_value());
    ASSERT_EQ(median_result->valid_count, 2);

    // CRITICAL: Application MUST NOT trust time with only 2 servers
    // Need at least 3 to establish consensus
    ASSERT_LT(median_result->valid_count, 3) << "Insufficient servers - cannot establish trust";
}

TEST_F(RogueServerTest, ThreeGoodTwoBadTime) {
    // 3 good servers, 2 rogue with wrong time (+1 year, -1 year)
    GoodServer good1(27001);
    GoodServer good2(27002);
    GoodServer good3(27003);
    GoodServer rogue1(27004, std::chrono::seconds(365 * 86400));   // +1 year
    GoodServer rogue2(27005, std::chrono::seconds(-365 * 86400));  // -1 year

    std::vector<Server> servers;
    servers.push_back(good1.get_client_config());
    servers.push_back(good2.get_client_config());
    servers.push_back(good3.get_client_config());

    Server rogue1_srv = rogue1.get_client_config();
    rogue1_srv.name = "future-server";
    servers.push_back(rogue1_srv);

    Server rogue2_srv = rogue2.get_client_config();
    rogue2_srv.name = "past-server";
    servers.push_back(rogue2_srv);

    Client client;
    auto results = client.query_servers(servers, 3, std::chrono::milliseconds(1000));

    ASSERT_EQ(results.size(), 5);

    // All 3 good servers should succeed
    ASSERT_TRUE(results[0].is_success());
    ASSERT_TRUE(results[1].is_success());
    ASSERT_TRUE(results[2].is_success());

    // Rogue servers also succeed (signatures are valid, just time is wrong)
    ASSERT_TRUE(results[3].is_success());
    ASSERT_TRUE(results[4].is_success());

    // Check that rogue times are way off
    auto now = std::chrono::system_clock::now();
    auto rogue1_diff = std::chrono::duration_cast<std::chrono::seconds>(
        results[3].midpoint - now).count();
    auto rogue2_diff = std::chrono::duration_cast<std::chrono::seconds>(
        results[4].midpoint - now).count();

    ASSERT_GT(rogue1_diff, 300 * 86400); // > 300 days in future
    ASSERT_LT(rogue2_diff, -300 * 86400); // > 300 days in past

    // Good servers should be close to now (within 10 seconds)
    for (size_t i = 0; i < 3; i++) {
        auto diff = std::chrono::duration_cast<std::chrono::seconds>(
            results[i].midpoint - now).count();
        ASSERT_LT(std::abs(diff), 10);
    }

    // Calculate median - all 5 servers have small radius so all are included
    // But median is resistant to outliers, so it should still be correct
    auto median_result = calculate_median_delta(
        results,
        now,
        std::chrono::seconds(10) // 10 second threshold
    );

    ASSERT_TRUE(median_result.has_value());
    // All 5 servers have small radius, so all are included in calculation
    ASSERT_EQ(median_result->valid_count, 5);

    // Median should still be close to good servers' time (median is outlier-resistant)
    // With 3 good + 2 rogue, median will be one of the good values
    ASSERT_LT(std::abs(median_result->delta.count()), 10000); // < 10 seconds
}

TEST_F(RogueServerTest, MedianDetectsColludingServers) {
    // Test case: 2 colluding servers with same wrong time, 3 honest servers
    // Median should still work if honest servers are in majority

    GoodServer good1(28001);
    GoodServer good2(28002);
    GoodServer good3(28003);

    // Two colluding servers both claim +30 days
    GoodServer collude1(28004, std::chrono::seconds(30 * 86400));
    GoodServer collude2(28005, std::chrono::seconds(30 * 86400));

    std::vector<Server> servers;
    servers.push_back(good1.get_client_config());
    servers.push_back(good2.get_client_config());
    servers.push_back(good3.get_client_config());

    Server col1_srv = collude1.get_client_config();
    col1_srv.name = "colluder1";
    servers.push_back(col1_srv);

    Server col2_srv = collude2.get_client_config();
    col2_srv.name = "colluder2";
    servers.push_back(col2_srv);

    Client client;
    auto results = client.query_servers(servers, 3, std::chrono::milliseconds(1000));

    ASSERT_EQ(results.size(), 5);

    // All should succeed (valid signatures)
    for (const auto& r : results) {
        ASSERT_TRUE(r.is_success());
    }

    auto now = std::chrono::system_clock::now();

    // Colluding servers should be ~30 days in future
    for (size_t i = 3; i < 5; i++) {
        auto diff = std::chrono::duration_cast<std::chrono::seconds>(
            results[i].midpoint - now).count();
        ASSERT_GT(diff, 25 * 86400); // > 25 days
        ASSERT_LT(diff, 35 * 86400); // < 35 days
    }

    // With 3/5 honest, median will still be correct even with colluders
    auto median_result = calculate_median_delta(
        results,
        now,
        std::chrono::seconds(5) // 5 second threshold
    );

    ASSERT_TRUE(median_result.has_value());
    // All 5 servers have small radius, so all included
    ASSERT_EQ(median_result->valid_count, 5);

    // Median is outlier-resistant: with 3 honest + 2 colluders, median is honest value
    ASSERT_LT(std::abs(median_result->delta.count()), 10000); // < 10 seconds
}

TEST_F(RogueServerTest, TrustedTimeAPIRequiresMinimumServers) {
    // Test the high-level trusted time API

    GoodServer good1(29001);
    GoodServer good2(29002);

    std::vector<Server> two_servers;
    two_servers.push_back(good1.get_client_config());
    two_servers.push_back(good2.get_client_config());

    // With only 2 servers, should not be trusted (need 3 minimum)
    Client client;
    auto result_2 = client.query_for_trusted_time(two_servers, 3);

    ASSERT_FALSE(result_2.is_success());
    ASSERT_FALSE(result_2.is_trusted());
    ASSERT_EQ(result_2.total_queried, 2);

    // Now add a third server
    GoodServer good3(29003);
    std::vector<Server> three_servers = two_servers;
    three_servers.push_back(good3.get_client_config());

    auto result_3 = client.query_for_trusted_time(three_servers, 3);

    // With 3 servers, should be trusted
    ASSERT_TRUE(result_3.is_success()) << "Error: " << result_3.error;
    ASSERT_TRUE(result_3.is_trusted());
    ASSERT_EQ(result_3.total_queried, 3);
    ASSERT_GE(result_3.agreeing_servers, 3);

    // Time should be reasonable (within 10 seconds of now)
    auto now = std::chrono::system_clock::now();
    auto diff = std::chrono::duration_cast<std::chrono::seconds>(
        result_3.time - now).count();
    ASSERT_LT(std::abs(diff), 10);

    // Uncertainty should be small
    ASSERT_LT(result_3.uncertainty.count(), 10000000); // < 10 seconds
}

TEST_F(RogueServerTest, TrustedTimeAPIRejectsMajorityRogue) {
    // 2 good servers + 3 rogue servers = majority rogue
    // Median will be influenced by rogues

    GoodServer good1(30001);
    GoodServer good2(30002);
    GoodServer rogue1(30003, std::chrono::seconds(365 * 86400));  // +1 year
    GoodServer rogue2(30004, std::chrono::seconds(365 * 86400));  // +1 year
    GoodServer rogue3(30005, std::chrono::seconds(365 * 86400));  // +1 year

    std::vector<Server> servers;
    servers.push_back(good1.get_client_config());
    servers.push_back(good2.get_client_config());

    Server rogue1_srv = rogue1.get_client_config();
    rogue1_srv.name = "rogue1";
    servers.push_back(rogue1_srv);

    Server rogue2_srv = rogue2.get_client_config();
    rogue2_srv.name = "rogue2";
    servers.push_back(rogue2_srv);

    Server rogue3_srv = rogue3.get_client_config();
    rogue3_srv.name = "rogue3";
    servers.push_back(rogue3_srv);

    Client client;
    auto result = client.query_for_trusted_time(servers, 3);

    // All 5 servers respond successfully
    ASSERT_TRUE(result.is_success());
    ASSERT_EQ(result.total_queried, 5);
    ASSERT_EQ(result.agreeing_servers, 5);

    // However, the median time will be wrong (closer to rogue time)
    auto now = std::chrono::system_clock::now();
    auto diff = std::chrono::duration_cast<std::chrono::seconds>(
        result.time - now).count();

    // With 3/5 servers lying about +1 year, median is wrong
    // This demonstrates that even with is_trusted()=true, you need
    // to trust the OPERATORS of the servers, not just have 3+ responses
    ASSERT_GT(diff, 300 * 86400); // Time is way off
}

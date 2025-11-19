// Copyright 2024
// SPDX-License-Identifier: Apache-2.0
//
// Grease Tests - RFC Section 7 compliance
// Verify client properly rejects all types of greased (invalid) responses

#include <roughtime/client.h>
#include <roughtime/server.h>
#include <gtest/gtest.h>
#include <thread>
#include <chrono>

using namespace roughtime;

class GreaseTest : public ::testing::Test {
protected:
    // Helper to create a test server with specific grease configuration
    struct GreaseTestServer {
        server::keygen::KeyPair root_keypair;
        std::unique_ptr<server::Server> server;
        std::thread thread;
        uint16_t port;

        GreaseTestServer(uint16_t p, server::GreaseType forced_grease_type)
            : port(p) {
            root_keypair = server::keygen::generate_keypair();

            server::ServerConfig config;
            config.address = "127.0.0.1";
            config.port = port;
            config.root_private_key = root_keypair.private_key;
            config.radius = std::chrono::seconds(1);
            config.cert_validity = std::chrono::hours(48);

            // Force 100% grease with specific type for testing
            config.enable_grease = true;
            config.grease_probability = 1.0;  // Always grease
            // Note: We can't force specific type yet, will always be random

            server = std::make_unique<server::Server>(config);
            thread = std::thread([this]() {
                server->run();
            });

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        ~GreaseTestServer() {
            if (server) {
                server->stop();
            }
            if (thread.joinable()) {
                thread.join();
            }
        }

        Server get_client_config() {
            Server srv;
            srv.name = "grease-test-server-" + std::to_string(port);
            srv.version = "IETF-Roughtime";
            srv.public_key = root_keypair.public_key;

            ServerAddress addr;
            addr.protocol = "udp";
            addr.address = "127.0.0.1:" + std::to_string(port);
            srv.addresses = {addr};

            return srv;
        }
    };
};

TEST_F(GreaseTest, ClientRejectsGreasedResponses) {
    // RFC Section 7: Servers SHOULD send invalid responses to test client validation
    // Clients MUST reject invalid responses

    // Create server with 100% grease probability
    server::keygen::KeyPair root_keypair = server::keygen::generate_keypair();

    server::ServerConfig config;
    config.address = "127.0.0.1";
    config.port = 40001;
    config.root_private_key = root_keypair.private_key;
    config.radius = std::chrono::seconds(1);
    config.cert_validity = std::chrono::hours(48);
    config.enable_grease = true;
    config.grease_probability = 1.0;  // Always send greased responses

    auto test_server = std::make_unique<server::Server>(config);
    std::thread server_thread([&test_server]() {
        test_server->run();
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Setup client
    Server srv;
    srv.name = "grease-server";
    srv.version = "IETF-Roughtime";
    srv.public_key = root_keypair.public_key;

    ServerAddress addr;
    addr.protocol = "udp";
    addr.address = "127.0.0.1:40001";
    srv.addresses = {addr};

    Client client;

    // Query multiple times - all should fail because all responses are greased
    int failed_count = 0;
    int attempts = 10;

    for (int i = 0; i < attempts; i++) {
        auto result = client.query(srv, 1, std::chrono::milliseconds(1000), std::nullopt);

        if (!result.is_success()) {
            failed_count++;
        }
    }

    // With 100% grease, client should reject MOST responses
    // UNDEFINED_TAG (1/5 types) should succeed (RFC: clients MUST ignore undefined tags)
    // Other 4 types should fail
    // Expected: ~80% failure, ~20% success (with random variance)
    EXPECT_GE(failed_count, attempts * 0.5);  // At least 50% should fail
    EXPECT_GT(failed_count, 0);  // Some failures
    EXPECT_LT(failed_count, attempts);  // But not all (UNDEFINED_TAG should pass)

    test_server->stop();
    if (server_thread.joinable()) {
        server_thread.join();
    }
}

TEST_F(GreaseTest, NormalServerWithLowGreaseStillWorks) {
    // RFC Section 7: Normal operation should work with occasional grease
    // Client should handle the mix of valid and invalid responses

    server::keygen::KeyPair root_keypair = server::keygen::generate_keypair();

    server::ServerConfig config;
    config.address = "127.0.0.1";
    config.port = 40002;
    config.root_private_key = root_keypair.private_key;
    config.radius = std::chrono::seconds(1);
    config.cert_validity = std::chrono::hours(48);
    config.enable_grease = true;
    config.grease_probability = 0.1;  // 10% grease (default)

    auto test_server = std::make_unique<server::Server>(config);
    std::thread server_thread([&test_server]() {
        test_server->run();
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    Server srv;
    srv.name = "normal-server-with-grease";
    srv.version = "IETF-Roughtime";
    srv.public_key = root_keypair.public_key;

    ServerAddress addr;
    addr.protocol = "udp";
    addr.address = "127.0.0.1:40002";
    srv.addresses = {addr};

    Client client;

    // Query multiple times
    int success_count = 0;
    int failed_count = 0;
    int attempts = 50;

    for (int i = 0; i < attempts; i++) {
        auto result = client.query(srv, 1, std::chrono::milliseconds(1000), std::nullopt);

        if (result.is_success()) {
            success_count++;
        } else {
            failed_count++;
        }
    }

    // With 10% grease, we expect ~90% success, ~10% failure
    // Allow for randomness
    EXPECT_GT(success_count, attempts * 0.75);  // At least 75% should succeed
    EXPECT_GT(failed_count, 0);  // At least some should fail (greased)
    EXPECT_LT(failed_count, attempts * 0.25);  // No more than 25% should fail

    test_server->stop();
    if (server_thread.joinable()) {
        server_thread.join();
    }
}

TEST_F(GreaseTest, DisabledGreaseWorks) {
    // Verify grease can be disabled for deterministic testing

    server::keygen::KeyPair root_keypair = server::keygen::generate_keypair();

    server::ServerConfig config;
    config.address = "127.0.0.1";
    config.port = 40003;
    config.root_private_key = root_keypair.private_key;
    config.radius = std::chrono::seconds(1);
    config.cert_validity = std::chrono::hours(48);
    config.enable_grease = false;  // Disabled

    auto test_server = std::make_unique<server::Server>(config);
    std::thread server_thread([&test_server]() {
        test_server->run();
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    Server srv;
    srv.name = "no-grease-server";
    srv.version = "IETF-Roughtime";
    srv.public_key = root_keypair.public_key;

    ServerAddress addr;
    addr.protocol = "udp";
    addr.address = "127.0.0.1:40003";
    srv.addresses = {addr};

    Client client;

    // All queries should succeed
    for (int i = 0; i < 10; i++) {
        auto result = client.query(srv, 1, std::chrono::milliseconds(1000), std::nullopt);
        ASSERT_TRUE(result.is_success()) << "Query " << i << " failed when grease is disabled";
    }

    test_server->stop();
    if (server_thread.joinable()) {
        server_thread.join();
    }
}

// Test each individual grease type to ensure client properly rejects them
TEST_F(GreaseTest, GreaseType_MissingMandatoryTag) {
    // RFC Section 7: Test MISSING_MANDATORY_TAG
    // Server omits mandatory tags (NONC, MIDP, RADI)
    server::keygen::KeyPair root_keypair = server::keygen::generate_keypair();

    server::ServerConfig config;
    config.address = "127.0.0.1";
    config.port = 40004;
    config.root_private_key = root_keypair.private_key;
    config.radius = std::chrono::seconds(1);
    config.cert_validity = std::chrono::hours(48);
    config.enable_grease = true;
    config.grease_probability = 1.0;  // Always grease
    config.forced_grease_type = server::GreaseType::MISSING_MANDATORY_TAG;

    auto test_server = std::make_unique<server::Server>(config);
    std::thread server_thread([&test_server]() {
        test_server->run();
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    Server srv;
    srv.name = "grease-missing-tag";
    srv.version = "IETF-Roughtime";
    srv.public_key = root_keypair.public_key;

    ServerAddress addr;
    addr.protocol = "udp";
    addr.address = "127.0.0.1:40004";
    srv.addresses = {addr};

    Client client;

    // Client should reject (single attempt, no retry within test)
    auto result = client.query(srv, 1, std::chrono::milliseconds(1000), std::nullopt);
    EXPECT_FALSE(result.is_success()) << "Client should reject response with missing mandatory tags";

    test_server->stop();
    if (server_thread.joinable()) {
        server_thread.join();
    }
}

TEST_F(GreaseTest, GreaseType_WrongVersion) {
    // RFC Section 7: Test WRONG_VERSION
    // Server sends VER not in client request
    server::keygen::KeyPair root_keypair = server::keygen::generate_keypair();

    server::ServerConfig config;
    config.address = "127.0.0.1";
    config.port = 40005;
    config.root_private_key = root_keypair.private_key;
    config.radius = std::chrono::seconds(1);
    config.cert_validity = std::chrono::hours(48);
    config.enable_grease = true;
    config.grease_probability = 1.0;
    config.forced_grease_type = server::GreaseType::WRONG_VERSION;

    auto test_server = std::make_unique<server::Server>(config);
    std::thread server_thread([&test_server]() {
        test_server->run();
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    Server srv;
    srv.name = "grease-wrong-version";
    srv.version = "IETF-Roughtime";
    srv.public_key = root_keypair.public_key;

    ServerAddress addr;
    addr.protocol = "udp";
    addr.address = "127.0.0.1:40005";
    srv.addresses = {addr};

    Client client;

    auto result = client.query(srv, 1, std::chrono::milliseconds(1000), std::nullopt);
    EXPECT_FALSE(result.is_success()) << "Client should reject response with wrong version";

    test_server->stop();
    if (server_thread.joinable()) {
        server_thread.join();
    }
}

TEST_F(GreaseTest, GreaseType_UndefinedTag) {
    // RFC Section 7: Test UNDEFINED_TAG
    // Server adds undefined/random tags
    // Note: Client MUST ignore undefined tags per RFC, so this should actually succeed
    server::keygen::KeyPair root_keypair = server::keygen::generate_keypair();

    server::ServerConfig config;
    config.address = "127.0.0.1";
    config.port = 40006;
    config.root_private_key = root_keypair.private_key;
    config.radius = std::chrono::seconds(1);
    config.cert_validity = std::chrono::hours(48);
    config.enable_grease = true;
    config.grease_probability = 1.0;
    config.forced_grease_type = server::GreaseType::UNDEFINED_TAG;

    auto test_server = std::make_unique<server::Server>(config);
    std::thread server_thread([&test_server]() {
        test_server->run();
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    Server srv;
    srv.name = "grease-undefined-tag";
    srv.version = "IETF-Roughtime";
    srv.public_key = root_keypair.public_key;

    ServerAddress addr;
    addr.protocol = "udp";
    addr.address = "127.0.0.1:40006";
    srv.addresses = {addr};

    Client client;

    auto result = client.query(srv, 1, std::chrono::milliseconds(1000), std::nullopt);
    // RFC: Clients MUST ignore undefined tags, so this should succeed
    EXPECT_TRUE(result.is_success()) << "Client should ignore undefined tags and accept valid response";

    test_server->stop();
    if (server_thread.joinable()) {
        server_thread.join();
    }
}

TEST_F(GreaseTest, GreaseType_InvalidCertSig) {
    // RFC Section 7: Test INVALID_CERT_SIG
    // Server corrupts certificate signature + wrong time
    server::keygen::KeyPair root_keypair = server::keygen::generate_keypair();

    server::ServerConfig config;
    config.address = "127.0.0.1";
    config.port = 40007;
    config.root_private_key = root_keypair.private_key;
    config.radius = std::chrono::seconds(1);
    config.cert_validity = std::chrono::hours(48);
    config.enable_grease = true;
    config.grease_probability = 1.0;
    config.forced_grease_type = server::GreaseType::INVALID_CERT_SIG;

    auto test_server = std::make_unique<server::Server>(config);
    std::thread server_thread([&test_server]() {
        test_server->run();
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    Server srv;
    srv.name = "grease-invalid-cert";
    srv.version = "IETF-Roughtime";
    srv.public_key = root_keypair.public_key;

    ServerAddress addr;
    addr.protocol = "udp";
    addr.address = "127.0.0.1:40007";
    srv.addresses = {addr};

    Client client;

    auto result = client.query(srv, 1, std::chrono::milliseconds(1000), std::nullopt);
    EXPECT_FALSE(result.is_success()) << "Client should reject response with invalid certificate signature";

    test_server->stop();
    if (server_thread.joinable()) {
        server_thread.join();
    }
}

TEST_F(GreaseTest, GreaseType_InvalidSrepSig) {
    // RFC Section 7: Test INVALID_SREP_SIG
    // Server corrupts SREP signature + wrong time
    server::keygen::KeyPair root_keypair = server::keygen::generate_keypair();

    server::ServerConfig config;
    config.address = "127.0.0.1";
    config.port = 40008;
    config.root_private_key = root_keypair.private_key;
    config.radius = std::chrono::seconds(1);
    config.cert_validity = std::chrono::hours(48);
    config.enable_grease = true;
    config.grease_probability = 1.0;
    config.forced_grease_type = server::GreaseType::INVALID_SREP_SIG;

    auto test_server = std::make_unique<server::Server>(config);
    std::thread server_thread([&test_server]() {
        test_server->run();
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    Server srv;
    srv.name = "grease-invalid-srep";
    srv.version = "IETF-Roughtime";
    srv.public_key = root_keypair.public_key;

    ServerAddress addr;
    addr.protocol = "udp";
    addr.address = "127.0.0.1:40008";
    srv.addresses = {addr};

    Client client;

    auto result = client.query(srv, 1, std::chrono::milliseconds(1000), std::nullopt);
    EXPECT_FALSE(result.is_success()) << "Client should reject response with invalid SREP signature";

    test_server->stop();
    if (server_thread.joinable()) {
        server_thread.join();
    }
}

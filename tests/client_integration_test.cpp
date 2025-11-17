// Copyright 2024
// SPDX-License-Identifier: Apache-2.0
//
// Client Integration Tests - Server runs as fixture

#include <roughtime/client.h>
#include <roughtime/server.h>
#include <gtest/gtest.h>
#include <thread>
#include <chrono>
#include <atomic>

using namespace roughtime;

// Global server fixture - starts once for all tests
class ClientIntegrationEnvironment : public ::testing::Environment {
public:
    static constexpr uint16_t TEST_PORT = 19999;
    static server::keygen::KeyPair root_keypair;
    static std::unique_ptr<server::Server> server_instance;
    static std::thread server_thread;
    static std::atomic<bool> server_ready;

    void SetUp() override {
        // Generate root keypair
        root_keypair = server::keygen::generate_keypair();

        // Configure server
        server::ServerConfig config;
        config.address = "127.0.0.1";
        config.port = TEST_PORT;
        config.root_private_key = root_keypair.private_key;
        config.radius = std::chrono::seconds(1);
        config.cert_validity = std::chrono::hours(48);
        config.rate_limit.enabled = false;  // Disable rate limiting for tests

        // Start server in background thread
        server_instance = std::make_unique<server::Server>(config);
        server_ready = false;

        server_thread = std::thread([&]() {
            server_ready = true;
            server_instance->run();
        });

        // Wait for server to be ready
        while (!server_ready) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    void TearDown() override {
        if (server_instance) {
            server_instance->stop();
        }
        if (server_thread.joinable()) {
            server_thread.join();
        }
    }
};

server::keygen::KeyPair ClientIntegrationEnvironment::root_keypair;
std::unique_ptr<server::Server> ClientIntegrationEnvironment::server_instance;
std::thread ClientIntegrationEnvironment::server_thread;
std::atomic<bool> ClientIntegrationEnvironment::server_ready{false};

class ClientIntegrationTest : public ::testing::Test {
protected:
    Server create_test_server(const std::string& version) {
        Server srv;
        srv.name = "test-server";
        srv.version = version;
        srv.public_key = ClientIntegrationEnvironment::root_keypair.public_key;

        ServerAddress addr;
        addr.protocol = "udp";
        addr.address = "127.0.0.1:" + std::to_string(ClientIntegrationEnvironment::TEST_PORT);
        srv.addresses = {addr};

        return srv;
    }
};

TEST_F(ClientIntegrationTest, QueryIETFRoughtime) {
    auto srv = create_test_server("IETF-Roughtime");
    Client client;

    auto result = client.query(srv, 3, std::chrono::milliseconds(1000), std::nullopt);

    ASSERT_TRUE(result.is_success());
    ASSERT_GT(result.midpoint.time_since_epoch().count(), 0);
    ASSERT_GT(result.radius.count(), 0);
    ASSERT_LE(result.radius.count(), std::chrono::microseconds(2000000).count());
}

TEST_F(ClientIntegrationTest, QueryGoogleRoughtime) {
    auto srv = create_test_server("Google-Roughtime");
    Client client;

    auto result = client.query(srv, 3, std::chrono::milliseconds(1000), std::nullopt);

    ASSERT_TRUE(result.is_success());
    ASSERT_GT(result.midpoint.time_since_epoch().count(), 0);
}

TEST_F(ClientIntegrationTest, MultipleSequentialQueries) {
    auto srv = create_test_server("IETF-Roughtime");
    Client client;

    for (int i = 0; i < 5; i++) {
        auto result = client.query(srv, 3, std::chrono::milliseconds(1000), std::nullopt);
        ASSERT_TRUE(result.is_success()) << "Query " << i << " failed";
    }
}

TEST_F(ClientIntegrationTest, ChainedQueries) {
    auto srv = create_test_server("IETF-Roughtime");
    Client client;

    auto result1 = client.query(srv, 3, std::chrono::milliseconds(1000), std::nullopt);
    ASSERT_TRUE(result1.is_success());

    // Sleep long enough to ensure different timestamps (1 second resolution for IETF)
    std::this_thread::sleep_for(std::chrono::seconds(2));

    auto result2 = client.query(srv, 3, std::chrono::milliseconds(1000), result1);
    ASSERT_TRUE(result2.is_success());

    // Times should be different
    ASSERT_NE(result1.midpoint, result2.midpoint);
}

TEST_F(ClientIntegrationTest, TimeAccuracy) {
    auto srv = create_test_server("IETF-Roughtime");
    Client client;

    auto before = std::chrono::system_clock::now();
    auto result = client.query(srv, 3, std::chrono::milliseconds(1000), std::nullopt);
    auto after = std::chrono::system_clock::now();

    ASSERT_TRUE(result.is_success());

    // Account for radius when checking time bounds
    auto before_with_margin = before - std::chrono::duration_cast<std::chrono::system_clock::duration>(result.radius);
    auto after_with_margin = after + std::chrono::duration_cast<std::chrono::system_clock::duration>(result.radius);

    ASSERT_GE(result.midpoint, before_with_margin);
    ASSERT_LE(result.midpoint, after_with_margin);
}

TEST_F(ClientIntegrationTest, InvalidPublicKey) {
    auto srv = create_test_server("IETF-Roughtime");
    srv.public_key = {}; // Wrong key

    Client client;
    auto result = client.query(srv, 3, std::chrono::milliseconds(1000), std::nullopt);

    ASSERT_FALSE(result.is_success());
}

TEST_F(ClientIntegrationTest, WrongPort) {
    auto srv = create_test_server("IETF-Roughtime");

    ServerAddress addr;
    addr.protocol = "udp";
    addr.address = "127.0.0.1:" + std::to_string(ClientIntegrationEnvironment::TEST_PORT + 1);
    srv.addresses = {addr};

    Client client;
    auto result = client.query(srv, 2, std::chrono::milliseconds(500), std::nullopt);

    ASSERT_FALSE(result.is_success());
}

TEST_F(ClientIntegrationTest, ResponseLatency) {
    auto srv = create_test_server("IETF-Roughtime");
    Client client;

    auto start = std::chrono::steady_clock::now();
    auto result = client.query(srv, 3, std::chrono::milliseconds(1000), std::nullopt);
    auto end = std::chrono::steady_clock::now();

    ASSERT_TRUE(result.is_success());

    auto latency = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    ASSERT_LT(latency.count(), 100);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::AddGlobalTestEnvironment(new ClientIntegrationEnvironment);
    return RUN_ALL_TESTS();
}

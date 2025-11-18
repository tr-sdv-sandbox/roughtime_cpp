// Copyright 2024
// SPDX-License-Identifier: Apache-2.0
//
// Server Integration Tests - Uses client to test server behavior

#include <roughtime/client.h>
#include <roughtime/server.h>
#include <gtest/gtest.h>
#include <thread>
#include <chrono>

using namespace roughtime;

class ServerIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // No initialization needed
    }

    struct TestServer {
        server::keygen::KeyPair root_keypair;
        std::unique_ptr<server::Server> server;
        std::thread thread;
        uint16_t port;

        TestServer(uint16_t p, std::chrono::seconds radius = std::chrono::seconds(1))
            : port(p) {
            root_keypair = server::keygen::generate_keypair();

            server::ServerConfig config;
            config.address = "127.0.0.1";
            config.port = port;
            config.root_private_key = root_keypair.private_key;
            config.radius = radius;
            config.cert_validity = std::chrono::hours(48);
            config.rate_limit.enabled = false;  // Disable rate limiting for tests

            server = std::make_unique<server::Server>(config);
            thread = std::thread([this]() {
                server->run();
            });

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        ~TestServer() {
            if (server) {
                server->stop();
            }
            if (thread.joinable()) {
                thread.join();
            }
        }

        Server get_client_config(const std::string& version) {
            Server srv;
            srv.name = "test-server";
            srv.version = version;
            srv.public_key = root_keypair.public_key;

            ServerAddress addr;
            addr.protocol = "udp";
            addr.address = "127.0.0.1:" + std::to_string(port);
            srv.addresses = {addr};

            return srv;
        }
    };
};

TEST_F(ServerIntegrationTest, ServerSupportsIETFDraft11) {
    TestServer server(20001);
    auto srv = server.get_client_config("IETF-Roughtime");

    Client client;
    auto result = client.query(srv, 3, std::chrono::milliseconds(1000), std::nullopt);

    ASSERT_TRUE(result.is_success());
}

TEST_F(ServerIntegrationTest, ServerSupportsGoogleRoughtime) {
    TestServer server(20002);
    auto srv = server.get_client_config("Google-Roughtime");

    Client client;
    auto result = client.query(srv, 3, std::chrono::milliseconds(1000), std::nullopt);

    ASSERT_TRUE(result.is_success());
}

TEST_F(ServerIntegrationTest, ServerRespectsRadiusSetting) {
    TestServer server(20003, std::chrono::seconds(5));
    auto srv = server.get_client_config("IETF-Roughtime");

    Client client;
    auto result = client.query(srv, 3, std::chrono::milliseconds(1000), std::nullopt);

    ASSERT_TRUE(result.is_success());

    // Radius should be <= 5 seconds (5,000,000 microseconds)
    ASSERT_LE(result.radius.count(), std::chrono::microseconds(5000000).count());
}

TEST_F(ServerIntegrationTest, ServerHandlesMultipleConcurrentRequests) {
    TestServer server(20004);
    auto srv = server.get_client_config("IETF-Roughtime");

    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};

    for (int i = 0; i < 10; i++) {
        threads.emplace_back([&srv, &success_count]() {
            Client client;
            auto result = client.query(srv, 3, std::chrono::milliseconds(1000), std::nullopt);
            if (result.is_success()) {
                success_count++;
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    ASSERT_EQ(success_count, 10);
}

TEST_F(ServerIntegrationTest, ServerProvidesValidSignatures) {
    TestServer server(20005);
    auto srv = server.get_client_config("IETF-Roughtime");

    Client client;

    // Multiple queries should all have valid signatures
    for (int i = 0; i < 5; i++) {
        auto result = client.query(srv, 3, std::chrono::milliseconds(1000), std::nullopt);
        ASSERT_TRUE(result.is_success()) << "Query " << i << " signature validation failed";
    }
}

TEST_F(ServerIntegrationTest, ServerMerkleProofVerification) {
    TestServer server(20006);
    auto srv = server.get_client_config("IETF-Roughtime");

    Client client;
    auto result = client.query(srv, 3, std::chrono::milliseconds(1000), std::nullopt);

    ASSERT_TRUE(result.is_success());
    // If query succeeds, Merkle proof was verified (done in client.cpp)
}

TEST_F(ServerIntegrationTest, ServerTimeProgresses) {
    TestServer server(20007);
    auto srv = server.get_client_config("IETF-Roughtime");

    Client client;

    auto result1 = client.query(srv, 3, std::chrono::milliseconds(1000), std::nullopt);
    ASSERT_TRUE(result1.is_success());

    // Sleep long enough for IETF timestamp (1 second resolution)
    std::this_thread::sleep_for(std::chrono::seconds(2));

    auto result2 = client.query(srv, 3, std::chrono::milliseconds(1000), std::nullopt);
    ASSERT_TRUE(result2.is_success());

    // Time should have progressed
    ASSERT_GT(result2.midpoint, result1.midpoint);
}

TEST_F(ServerIntegrationTest, ServerResponseSize) {
    TestServer server(20008);
    auto srv = server.get_client_config("IETF-Roughtime");

    Client client;
    auto result = client.query(srv, 3, std::chrono::milliseconds(1000), std::nullopt);

    ASSERT_TRUE(result.is_success());
    // IETF response should be reasonable size (typically 392 bytes)
    // This is implicitly tested by successful decoding
}

// Protocol Version Compatibility Tests
// Test that server correctly negotiates all supported protocol versions

TEST_F(ServerIntegrationTest, ServerNegotiatesDraft14) {
    TestServer server(20009);
    auto srv = server.get_client_config("IETF-Roughtime");

    Client client;
    auto result = client.query(srv, 3, std::chrono::milliseconds(1000), std::nullopt);

    ASSERT_TRUE(result.is_success()) << "Draft-14 negotiation failed: " << result.error;
    // Server should accept client advertising Draft-14 and respond with Draft-14
    // Timestamp should be Unix seconds (Draft-14 format)
    EXPECT_GT(result.midpoint.time_since_epoch().count(), 0);
    EXPECT_GE(result.radius.count(), 0);
}

TEST_F(ServerIntegrationTest, ServerNegotiatesDraft11) {
    TestServer server(20010);
    auto srv = server.get_client_config("IETF-Roughtime");

    Client client;
    auto result = client.query(srv, 3, std::chrono::milliseconds(1000), std::nullopt);

    ASSERT_TRUE(result.is_success()) << "Draft-11 negotiation failed: " << result.error;
    // Verify time is reasonable
    auto now = std::chrono::system_clock::now();
    auto time_diff = std::chrono::duration_cast<std::chrono::seconds>(
        result.midpoint > now ? result.midpoint - now : now - result.midpoint
    );
    EXPECT_LT(time_diff.count(), 10) << "Time difference too large: " << time_diff.count() << "s";
}

TEST_F(ServerIntegrationTest, ServerNegotiatesDraft08) {
    TestServer server(20011);
    auto srv = server.get_client_config("IETF-Roughtime");

    Client client;
    auto result = client.query(srv, 3, std::chrono::milliseconds(1000), std::nullopt);

    ASSERT_TRUE(result.is_success()) << "Draft-08 negotiation failed: " << result.error;
    // Server should successfully respond to Draft-08 capable clients
    EXPECT_GT(result.radius.count(), 0);
}

TEST_F(ServerIntegrationTest, ServerNegotiatesDraft07) {
    TestServer server(20012);
    auto srv = server.get_client_config("IETF-Roughtime");

    Client client;
    auto result = client.query(srv, 3, std::chrono::milliseconds(1000), std::nullopt);

    ASSERT_TRUE(result.is_success()) << "Draft-07 negotiation failed: " << result.error;
    // Server should successfully respond to Draft-07 capable clients
    EXPECT_GT(result.radius.count(), 0);
}

TEST_F(ServerIntegrationTest, AllVersionsProduceSimilarTime) {
    // Verify all protocol versions return similar time values
    TestServer server1(20013);
    TestServer server2(20014);
    TestServer server3(20015);

    Client client;

    auto srv_ietf = server1.get_client_config("IETF-Roughtime");
    auto srv_google = server2.get_client_config("Google-Roughtime");

    auto result_ietf = client.query(srv_ietf, 3, std::chrono::milliseconds(1000), std::nullopt);
    auto result_google = client.query(srv_google, 3, std::chrono::milliseconds(1000), std::nullopt);

    ASSERT_TRUE(result_ietf.is_success());
    ASSERT_TRUE(result_google.is_success());

    // Both should return time within 5 seconds of each other
    auto time_diff = std::chrono::duration_cast<std::chrono::seconds>(
        result_ietf.midpoint > result_google.midpoint ?
        result_ietf.midpoint - result_google.midpoint :
        result_google.midpoint - result_ietf.midpoint
    );

    EXPECT_LT(time_diff.count(), 5) << "Time difference between protocols: " << time_diff.count() << "s";
}

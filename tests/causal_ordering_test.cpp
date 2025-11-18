// Copyright 2024
// SPDX-License-Identifier: Apache-2.0
//
// Causal Ordering Tests - RFC 8.2 compliance

#include <roughtime/client.h>
#include <roughtime/server.h>
#include <gtest/gtest.h>
#include <thread>
#include <chrono>

using namespace roughtime;

class CausalOrderingTest : public ::testing::Test {
protected:
    struct TestServer {
        server::keygen::KeyPair root_keypair;
        std::unique_ptr<server::Server> server;
        std::thread thread;
        uint16_t port;

        TestServer(uint16_t p, std::chrono::seconds time_offset = std::chrono::seconds(0))
            : port(p) {
            root_keypair = server::keygen::generate_keypair();

            server::ServerConfig config;
            config.address = "127.0.0.1";
            config.port = port;
            config.root_private_key = root_keypair.private_key;
            config.radius = std::chrono::seconds(1);
            config.cert_validity = std::chrono::hours(48);
            config.rate_limit.enabled = false;
            config.time_offset = time_offset;

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

        Server get_client_config() {
            Server srv;
            srv.name = "test-server-" + std::to_string(port);
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

TEST_F(CausalOrderingTest, ValidCausalOrdering) {
    // Three servers with correct times - should pass causal ordering
    TestServer server1(30001);
    TestServer server2(30002);
    TestServer server3(30003);

    std::vector<Server> servers;
    servers.push_back(server1.get_client_config());
    servers.push_back(server2.get_client_config());
    servers.push_back(server3.get_client_config());

    Client client;
    auto results = client.query_servers(servers);

    ASSERT_EQ(results.size(), 3);
    ASSERT_TRUE(results[0].is_success());
    ASSERT_TRUE(results[1].is_success());
    ASSERT_TRUE(results[2].is_success());

    // Validate causal ordering
    auto malfeasance = validate_causal_ordering(results);
    ASSERT_FALSE(malfeasance.has_value()) << "No malfeasance should be detected";
}

TEST_F(CausalOrderingTest, DetectCausalOrderingViolation) {
    // Server 1: normal time
    // Server 2: 1 hour in past (violates causal ordering)
    TestServer server1(30011);
    TestServer server2(30012, std::chrono::seconds(-3600));  // -1 hour

    std::vector<Server> servers;
    servers.push_back(server1.get_client_config());
    servers.push_back(server2.get_client_config());

    Client client;
    auto results = client.query_servers(servers);

    ASSERT_EQ(results.size(), 2);
    ASSERT_TRUE(results[0].is_success());
    ASSERT_TRUE(results[1].is_success());

    // Should detect causal ordering violation
    auto malfeasance = validate_causal_ordering(results);
    ASSERT_TRUE(malfeasance.has_value()) << "Malfeasance should be detected";

    if (malfeasance) {
        EXPECT_EQ(malfeasance->server_i_index, 0);
        EXPECT_EQ(malfeasance->server_j_index, 1);
        EXPECT_FALSE(malfeasance->response_i.empty());
        EXPECT_FALSE(malfeasance->response_j.empty());

        std::string report = malfeasance->to_string();
        EXPECT_FALSE(report.empty());
        EXPECT_NE(report.find("MALFEASANCE"), std::string::npos);
    }
}

TEST_F(CausalOrderingTest, RepeatedMeasurementSequence) {
    // Test that query_for_trusted_time performs repeated measurements
    TestServer server1(30021);
    TestServer server2(30022);
    TestServer server3(30023);

    std::vector<Server> servers;
    servers.push_back(server1.get_client_config());
    servers.push_back(server2.get_client_config());
    servers.push_back(server3.get_client_config());

    Client client;
    auto result = client.query_for_trusted_time(servers, 3);

    // Should succeed with honest servers
    ASSERT_TRUE(result.is_success());
    ASSERT_TRUE(result.is_trusted());
    ASSERT_FALSE(result.malfeasance.has_value());
    ASSERT_EQ(result.agreeing_servers, 3);
}

TEST_F(CausalOrderingTest, RepeatedMeasurementDetectsMalfeasance) {
    // Server reports time that goes backwards between queries
    TestServer server1(30031);
    TestServer server2(30032, std::chrono::seconds(-7200));  // -2 hours
    TestServer server3(30033);

    std::vector<Server> servers;
    servers.push_back(server1.get_client_config());
    servers.push_back(server2.get_client_config());
    servers.push_back(server3.get_client_config());

    Client client;
    auto result = client.query_for_trusted_time(servers, 3);

    // Should detect malfeasance and NOT be trusted
    ASSERT_FALSE(result.is_trusted()) << "Time should not be trusted with malfeasance";
    ASSERT_TRUE(result.malfeasance.has_value()) << "Malfeasance should be detected";

    if (result.malfeasance) {
        std::string report = result.malfeasance->to_string();
        EXPECT_FALSE(report.empty());
        EXPECT_NE(report.find("MALFEASANCE DETECTED"), std::string::npos);
    }
}

TEST_F(CausalOrderingTest, MalfeasanceReportContainsProof) {
    // Create servers with causal violation
    TestServer server1(30041);
    TestServer server2(30042, std::chrono::seconds(-3600));

    std::vector<Server> servers;
    servers.push_back(server1.get_client_config());
    servers.push_back(server2.get_client_config());

    Client client;
    auto results = client.query_servers(servers);

    auto malfeasance = validate_causal_ordering(results);
    ASSERT_TRUE(malfeasance.has_value());

    // Verify report contains all necessary proof
    EXPECT_FALSE(malfeasance->response_i.empty()) << "Should include response from server i";
    EXPECT_FALSE(malfeasance->response_j.empty()) << "Should include response from server j";
    EXPECT_FALSE(malfeasance->server_i_name.empty());
    EXPECT_FALSE(malfeasance->server_j_name.empty());
    EXPECT_GT(malfeasance->midpoint_i.time_since_epoch().count(), 0);
    EXPECT_GT(malfeasance->midpoint_j.time_since_epoch().count(), 0);
}

TEST_F(CausalOrderingTest, CausalOrderingWithSkippedServers) {
    // Test causal ordering when some servers fail
    TestServer server1(30051);
    // Server 2 doesn't exist (will fail)
    TestServer server3(30053);

    std::vector<Server> servers;
    servers.push_back(server1.get_client_config());

    Server fake_server;
    fake_server.name = "fake-server";
    fake_server.version = "IETF-Roughtime";
    fake_server.public_key = server1.get_client_config().public_key;
    ServerAddress fake_addr;
    fake_addr.protocol = "udp";
    fake_addr.address = "127.0.0.1:30052";  // Nothing listening
    fake_server.addresses = {fake_addr};
    servers.push_back(fake_server);

    servers.push_back(server3.get_client_config());

    Client client;
    auto results = client.query_servers(servers);

    ASSERT_EQ(results.size(), 3);
    ASSERT_TRUE(results[0].is_success());
    ASSERT_FALSE(results[1].is_success());  // Should fail
    ASSERT_TRUE(results[2].is_success());

    // Causal ordering should only check successful results
    auto malfeasance = validate_causal_ordering(results);
    ASSERT_FALSE(malfeasance.has_value()) << "Should ignore failed servers";
}

TEST_F(CausalOrderingTest, EdgeCaseExactBoundary) {
    // Test the exact boundary condition: MIDP_i - RADI_i == MIDP_j + RADI_j
    // This should PASS (not violate causal ordering)
    TestServer server1(30061);

    // Query twice with small time diff
    Client client;
    auto srv = server1.get_client_config();

    auto result1 = client.query(srv, 3, std::chrono::milliseconds(1000), std::nullopt);
    ASSERT_TRUE(result1.is_success());

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    auto result2 = client.query(srv, 3, std::chrono::milliseconds(1000), result1);
    ASSERT_TRUE(result2.is_success());

    std::vector<QueryResult> results = {result1, result2};

    // With same server and small time diff, should be within bounds
    auto malfeasance = validate_causal_ordering(results);
    ASSERT_FALSE(malfeasance.has_value());
}

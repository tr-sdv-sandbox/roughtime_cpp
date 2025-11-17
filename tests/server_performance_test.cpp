// Copyright 2024
// SPDX-License-Identifier: Apache-2.0
//
// Server Performance Tests - Measure throughput and latency

#include <roughtime/client.h>
#include <roughtime/server.h>
#include <gtest/gtest.h>
#include <thread>
#include <chrono>
#include <vector>
#include <atomic>
#include <future>
#include <iomanip>

using namespace roughtime;
using namespace std::chrono;

class ServerPerformanceTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Generate server keypair
        auto root_kp = server::keygen::generate_keypair();
        root_public_ = root_kp.public_key;

        // Configure and start server
        server::ServerConfig config;
        config.address = "127.0.0.1";
        config.port = 40000;
        config.root_private_key = root_kp.private_key;
        config.radius = std::chrono::seconds(1);
        config.cert_validity = std::chrono::hours(48);
        config.rate_limit.enabled = false;  // Disable rate limiting for performance tests

        server_ = std::make_unique<server::Server>(config);
        server_thread_ = std::thread([this]() {
            server_->run();
        });

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    void TearDown() override {
        if (server_) {
            server_->stop();
        }
        if (server_thread_.joinable()) {
            server_thread_.join();
        }
    }

    Server get_ietf_config() {
        Server srv;
        srv.name = "perf-test-ietf";
        srv.version = "IETF-Roughtime";
        srv.public_key = root_public_;
        srv.addresses = {{"udp", "127.0.0.1:40000"}};
        return srv;
    }

    Server get_google_config() {
        Server srv;
        srv.name = "perf-test-google";
        srv.version = "Google-Roughtime";
        srv.public_key = root_public_;
        srv.addresses = {{"udp", "127.0.0.1:40000"}};
        return srv;
    }

    std::array<uint8_t, 32> root_public_;
    std::unique_ptr<server::Server> server_;
    std::thread server_thread_;
};

struct PerfResult {
    size_t total_requests = 0;
    size_t successful_requests = 0;
    size_t failed_requests = 0;
    double duration_seconds = 0.0;
    double requests_per_second = 0.0;
    double avg_latency_ms = 0.0;
    double min_latency_ms = 0.0;
    double max_latency_ms = 0.0;
    double p50_latency_ms = 0.0;
    double p95_latency_ms = 0.0;
    double p99_latency_ms = 0.0;
};

PerfResult run_performance_test(
    const Server& server_config,
    size_t num_requests,
    size_t num_threads
) {
    PerfResult result;
    result.total_requests = num_requests;

    std::atomic<size_t> successful{0};
    std::atomic<size_t> failed{0};
    std::vector<double> latencies;
    std::mutex latencies_mutex;

    auto start_time = high_resolution_clock::now();

    // Distribute requests across threads
    size_t requests_per_thread = num_requests / num_threads;
    std::vector<std::future<void>> futures;

    for (size_t t = 0; t < num_threads; t++) {
        futures.push_back(std::async(std::launch::async, [&, t]() {
            Client client;
            size_t thread_requests = (t == num_threads - 1)
                ? requests_per_thread + (num_requests % num_threads)
                : requests_per_thread;

            for (size_t i = 0; i < thread_requests; i++) {
                auto req_start = high_resolution_clock::now();

                auto response = client.query(
                    server_config,
                    1,  // single attempt
                    std::chrono::milliseconds(1000)
                );

                auto req_end = high_resolution_clock::now();
                auto latency = static_cast<double>(duration_cast<microseconds>(req_end - req_start).count()) / 1000.0;

                if (response.is_success()) {
                    successful++;
                    std::lock_guard<std::mutex> lock(latencies_mutex);
                    latencies.push_back(latency);
                } else {
                    failed++;
                }
            }
        }));
    }

    // Wait for all threads to complete
    for (auto& f : futures) {
        f.wait();
    }

    auto end_time = high_resolution_clock::now();

    result.successful_requests = successful.load();
    result.failed_requests = failed.load();
    result.duration_seconds = static_cast<double>(duration_cast<microseconds>(end_time - start_time).count()) / 1000000.0;
    result.requests_per_second = static_cast<double>(result.successful_requests) / result.duration_seconds;

    // Calculate latency statistics
    if (!latencies.empty()) {
        std::sort(latencies.begin(), latencies.end());

        result.min_latency_ms = latencies.front();
        result.max_latency_ms = latencies.back();

        double sum = 0;
        for (auto l : latencies) {
            sum += l;
        }
        result.avg_latency_ms = sum / static_cast<double>(latencies.size());

        result.p50_latency_ms = latencies[latencies.size() * 50 / 100];
        result.p95_latency_ms = latencies[latencies.size() * 95 / 100];
        result.p99_latency_ms = latencies[latencies.size() * 99 / 100];
    }

    return result;
}

void print_result(const std::string& test_name, const PerfResult& result) {
    std::cout << "\n=== " << test_name << " ===\n";
    std::cout << "Total requests:      " << result.total_requests << "\n";
    std::cout << "Successful:          " << result.successful_requests << "\n";
    std::cout << "Failed:              " << result.failed_requests << "\n";
    std::cout << "Duration:            " << std::fixed << std::setprecision(2)
              << result.duration_seconds << " seconds\n";
    std::cout << "Throughput:          " << std::fixed << std::setprecision(0)
              << result.requests_per_second << " requests/sec\n";
    std::cout << "\nLatency (ms):\n";
    std::cout << "  Min:               " << std::fixed << std::setprecision(2)
              << result.min_latency_ms << " ms\n";
    std::cout << "  Avg:               " << std::fixed << std::setprecision(2)
              << result.avg_latency_ms << " ms\n";
    std::cout << "  P50:               " << std::fixed << std::setprecision(2)
              << result.p50_latency_ms << " ms\n";
    std::cout << "  P95:               " << std::fixed << std::setprecision(2)
              << result.p95_latency_ms << " ms\n";
    std::cout << "  P99:               " << std::fixed << std::setprecision(2)
              << result.p99_latency_ms << " ms\n";
    std::cout << "  Max:               " << std::fixed << std::setprecision(2)
              << result.max_latency_ms << " ms\n";
}

TEST_F(ServerPerformanceTest, SingleThreadedThroughput) {
    auto server_config = get_ietf_config();
    auto result = run_performance_test(server_config, 100, 1);

    print_result("Single-threaded IETF (100 requests, 1 thread)", result);

    ASSERT_GT(result.successful_requests, 95) << "Expected >95% success rate";
    ASSERT_GT(result.requests_per_second, 50) << "Expected >50 req/s single-threaded";
}

TEST_F(ServerPerformanceTest, ConcurrentThroughputIETF) {
    auto server_config = get_ietf_config();
    auto result = run_performance_test(server_config, 1000, 10);

    print_result("Concurrent IETF (1000 requests, 10 threads)", result);

    ASSERT_GT(result.successful_requests, 950) << "Expected >95% success rate";
    ASSERT_GT(result.requests_per_second, 200) << "Expected >200 req/s with concurrency";
    ASSERT_LT(result.avg_latency_ms, 100) << "Expected avg latency <100ms";
}

TEST_F(ServerPerformanceTest, ConcurrentThroughputGoogle) {
    auto server_config = get_google_config();
    auto result = run_performance_test(server_config, 1000, 10);

    print_result("Concurrent Google-Roughtime (1000 requests, 10 threads)", result);

    ASSERT_GT(result.successful_requests, 950) << "Expected >95% success rate";
    ASSERT_GT(result.requests_per_second, 200) << "Expected >200 req/s with concurrency";
}

TEST_F(ServerPerformanceTest, HighConcurrency) {
    auto server_config = get_ietf_config();
    auto result = run_performance_test(server_config, 2000, 20);

    print_result("High concurrency IETF (2000 requests, 20 threads)", result);

    ASSERT_GT(result.successful_requests, 1900) << "Expected >95% success rate";
    ASSERT_GT(result.requests_per_second, 300) << "Expected >300 req/s with high concurrency";
}

TEST_F(ServerPerformanceTest, BurstLoad) {
    // Test server's ability to handle sudden burst of requests
    auto server_config = get_ietf_config();

    // Send 500 requests as fast as possible with 50 threads
    auto result = run_performance_test(server_config, 500, 50);

    print_result("Burst load (500 requests, 50 threads)", result);

    // Even under burst, expect most requests to succeed
    ASSERT_GT(result.successful_requests, 450) << "Expected >90% success rate under burst";
}

TEST_F(ServerPerformanceTest, LatencyConsistency) {
    // Test that latency is consistent under moderate load
    auto server_config = get_ietf_config();
    auto result = run_performance_test(server_config, 500, 5);

    print_result("Latency consistency (500 requests, 5 threads)", result);

    ASSERT_GT(result.successful_requests, 475) << "Expected >95% success rate";

    // P99 should be under 20ms (good tail latency control)
    ASSERT_LT(result.p99_latency_ms, 20.0)
        << "P99 latency should be <20ms (tail latency)";

    // Average latency should be low
    ASSERT_LT(result.avg_latency_ms, 5.0)
        << "Average latency should be <5ms";
}

TEST_F(ServerPerformanceTest, ProtocolComparison) {
    // Compare IETF vs Google-Roughtime performance
    std::cout << "\n=== Protocol Performance Comparison ===\n";

    auto ietf_result = run_performance_test(get_ietf_config(), 500, 10);
    auto google_result = run_performance_test(get_google_config(), 500, 10);

    std::cout << "\nIETF-Roughtime:\n";
    std::cout << "  Throughput: " << std::fixed << std::setprecision(0)
              << ietf_result.requests_per_second << " req/s\n";
    std::cout << "  Avg latency: " << std::fixed << std::setprecision(2)
              << ietf_result.avg_latency_ms << " ms\n";

    std::cout << "\nGoogle-Roughtime:\n";
    std::cout << "  Throughput: " << std::fixed << std::setprecision(0)
              << google_result.requests_per_second << " req/s\n";
    std::cout << "  Avg latency: " << std::fixed << std::setprecision(2)
              << google_result.avg_latency_ms << " ms\n";

    // Both should perform reasonably well
    ASSERT_GT(ietf_result.requests_per_second, 100);
    ASSERT_GT(google_result.requests_per_second, 100);
}

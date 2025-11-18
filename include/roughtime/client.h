// Copyright 2024
// SPDX-License-Identifier: Apache-2.0
//
// Roughtime client implementation

#pragma once

#include "protocol.h"
#include "config.h"
#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace roughtime {

// Result of a Roughtime query
struct QueryResult {
    std::vector<uint8_t> request;
    std::vector<uint8_t> blind;
    std::vector<uint8_t> response;
    std::chrono::system_clock::time_point midpoint;
    std::chrono::seconds radius;  // Changed to seconds for draft-14 alignment
    std::chrono::milliseconds network_delay;
    const Server* server;
    std::string error;

    bool is_success() const noexcept { return error.empty(); }
};

// Malfeasance report - records causal ordering violation
struct MalfeasanceReport {
    size_t server_i_index;  // Earlier query index
    size_t server_j_index;  // Later query index
    std::string server_i_name;
    std::string server_j_name;
    std::chrono::system_clock::time_point midpoint_i;
    std::chrono::system_clock::time_point midpoint_j;
    std::chrono::seconds radius_i;
    std::chrono::seconds radius_j;
    std::vector<uint8_t> response_i;  // Full response for proof
    std::vector<uint8_t> response_j;  // Full response for proof

    std::string to_string() const;
};

// Result of querying multiple servers for trusted time
struct TrustedTimeResult {
    std::chrono::system_clock::time_point time;
    std::chrono::seconds uncertainty;  // Changed to seconds for draft-14 alignment
    size_t agreeing_servers;
    size_t total_queried;
    std::vector<QueryResult> all_results;
    std::optional<MalfeasanceReport> malfeasance;  // Set if causal ordering violated
    std::string error;

    bool is_trusted() const noexcept {
        // Require at least 3 successful servers to establish trust
        // AND no malfeasance detected
        return error.empty() && agreeing_servers >= 3 && !malfeasance.has_value();
    }

    bool is_success() const noexcept { return error.empty(); }
};

// Roughtime client
class Client {
public:
    Client();
    ~Client();

    // Query a single server (LOW-LEVEL API)
    //
    // WARNING: DO NOT trust time from a single server! Use query_for_trusted_time() instead.
    // This is a low-level API for advanced use cases (chaining, testing, etc.)
    //
    // A single server response is cryptographically valid but the server could be lying
    // about the time. Roughtime security requires querying multiple servers.
    QueryResult query(
        const Server& server,
        int attempts = 3,
        std::chrono::milliseconds timeout = std::chrono::milliseconds(1000),
        const std::optional<QueryResult>& prev = std::nullopt
    );

    // Query multiple servers in sequence (LOW-LEVEL API)
    //
    // WARNING: Use query_for_trusted_time() instead for secure time.
    // This returns individual results without computing consensus.
    std::vector<QueryResult> query_servers(
        const std::vector<Server>& servers,
        int attempts = 3,
        std::chrono::milliseconds timeout = std::chrono::milliseconds(1000)
    );

    // Query multiple servers and compute trusted time
    //
    // SECURITY: Single server responses CANNOT be trusted! An attacker could provide
    // any time value with valid cryptographic signatures. Roughtime security requires
    // querying multiple independent servers and computing the median.
    //
    // This function requires at least min_servers (default 3) successful responses
    // to return a trusted time. With fewer servers, the result is returned but
    // is_trusted() will be false.
    //
    // Parameters:
    //   servers: List of Roughtime servers to query (should be from different operators)
    //   min_servers: Minimum servers needed for trust (default 3, recommended 5+)
    //   attempts: Retry attempts per server (default 3)
    //   timeout: Timeout per attempt (default 1000ms)
    //   radius_threshold: Maximum acceptable uncertainty (default 10s)
    //
    // Returns:
    //   TrustedTimeResult with time if successful, check is_trusted() before using
    TrustedTimeResult query_for_trusted_time(
        const std::vector<Server>& servers,
        size_t min_servers = 3,
        int attempts = 3,
        std::chrono::milliseconds timeout = std::chrono::milliseconds(1000),
        std::chrono::seconds radius_threshold = std::chrono::seconds(10)
    );

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// Calculate median time delta from query results
struct MedianDeltaResult {
    std::chrono::milliseconds delta;
    size_t valid_count;
};

std::optional<MedianDeltaResult> calculate_median_delta(
    const std::vector<QueryResult>& results,
    std::chrono::system_clock::time_point reference_time,
    std::chrono::seconds radius_threshold
);

// Validate causal ordering of query results
// Per RFC 8.2: For each pair (i, j) where i received before j,
// must check: MIDP_i - RADI_i <= MIDP_j + RADI_j
// Returns nullopt if valid, or MalfeasanceReport if violation detected
std::optional<MalfeasanceReport> validate_causal_ordering(
    const std::vector<QueryResult>& results
);

} // namespace roughtime

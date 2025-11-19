// Copyright 2024
// SPDX-License-Identifier: Apache-2.0

#include "roughtime/client.h"
#include "roughtime/protocol.h"
#include "roughtime/util.h"
#include <glog/logging.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>
#include <memory>
#include <sstream>
#include <iomanip>
#include <random>

namespace roughtime {

class Client::Impl {
public:
    QueryResult query_server(
        const Server& server,
        int attempts,
        std::chrono::milliseconds timeout,
        const std::optional<QueryResult>& prev
    ) {
        LOG(INFO) << "Starting query for server: " << server.name;
        QueryResult result;
        result.server = &server;

        // Determine version preference
        std::vector<Version> version_pref;
        if (server.version == "IETF-Roughtime" || server.version.empty()) {
            // Prefer newest drafts first
            version_pref = {Version::Draft14, Version::Draft11, Version::Draft08, Version::Draft07};
            LOG(INFO) << "Using IETF-Roughtime protocol (advertising Draft-14, 11, 08, 07)";
        } else if (server.version == "Google-Roughtime") {
            version_pref = {Version::Google};
            LOG(INFO) << "Using Google-Roughtime protocol";
        } else {
            result.error = "Unknown version: " + server.version;
            LOG(ERROR) << "Unknown version: " + server.version;
            return result;
        }

        // Get previous reply if chaining
        std::vector<uint8_t> prev_reply;
        if (prev && prev->is_success()) {
            prev_reply = prev->response;
        }

        // Create request
        auto req_opt = create_request(version_pref, prev_reply, server.public_key);
        if (!req_opt) {
            result.error = "Failed to create request";
            LOG(ERROR) << "Failed to create request";
            return result;
        }

        result.request = req_opt->request_bytes;
        result.blind = req_opt->blind;

        // Find UDP address
        const ServerAddress* udp_addr = nullptr;
        for (const auto& addr : server.addresses) {
            if (addr.protocol == "udp" || addr.protocol == "udp4" || addr.protocol == "udp6") {
                udp_addr = &addr;
                break;
            }
        }

        if (!udp_addr) {
            result.error = "No UDP address found";
            LOG(ERROR) << "No UDP address found for server";
            return result;
        }

        // Parse address
        auto colon_pos = udp_addr->address.find_last_of(':');
        if (colon_pos == std::string::npos) {
            result.error = "Invalid address format";
            LOG(ERROR) << "Invalid address format: " << udp_addr->address;
            return result;
        }

        std::string host = udp_addr->address.substr(0, colon_pos);
        std::string port_str = udp_addr->address.substr(colon_pos + 1);

        // Remove brackets from IPv6 addresses
        if (!host.empty() && host.front() == '[' && host.back() == ']') {
            host = host.substr(1, host.size() - 2);
        }

        // Resolve address
        struct addrinfo hints{}, *res = nullptr;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;

        int gai_err = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
        if (gai_err != 0) {
            result.error = std::string("Failed to resolve address: ") + gai_strerror(gai_err);
            LOG(ERROR) << result.error;
            return result;
        }

        auto start_time = std::chrono::steady_clock::now();

        // Try to query the server
        std::vector<uint8_t> response;
        bool success = false;

        for (int attempt = 0; attempt < attempts && !success; attempt++) {
            util::SocketGuard sock(socket(res->ai_family, res->ai_socktype, res->ai_protocol));
            if (!sock.valid()) {
                LOG(WARNING) << "Failed to create socket: " << strerror(errno);
                continue;
            }

            // Set timeout
            struct timeval tv;
            tv.tv_sec = timeout.count() / 1000;
            tv.tv_usec = (timeout.count() % 1000) * 1000;
            if (setsockopt(sock.get(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
                LOG(WARNING) << "Failed to set socket timeout: " << strerror(errno);
            }

            // Send request
            ssize_t sent = sendto(sock.get(), result.request.data(), result.request.size(),
                                 0, res->ai_addr, res->ai_addrlen);

            if (sent < 0) {
                LOG(WARNING) << "sendto() failed: " << strerror(errno);
                continue;
            }

            // Receive response
            uint8_t buffer[2048];
            ssize_t received = recvfrom(sock.get(), buffer, sizeof(buffer), 0, nullptr, nullptr);

            if (received > 0) {
                response.assign(buffer, buffer + received);
                success = true;
            } else if (received < 0) {
                LOG(WARNING) << "recvfrom() failed: " << strerror(errno);
            } else {
                LOG(WARNING) << "Received 0 bytes (connection closed)";
            }
        }

        freeaddrinfo(res);

        auto end_time = std::chrono::steady_clock::now();
        result.network_delay = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - start_time
        );

        if (!success) {
            result.error = "No reply from server";
            LOG(ERROR) << "No reply received from server after " << attempts << " attempts";
            return result;
        }

        // Verify response
        auto verified = verify_reply(version_pref, response, server.public_key, req_opt->nonce);
        if (!verified) {
            result.error = "Failed to verify response";
            LOG(ERROR) << "Response verification failed";
            return result;
        }

        result.response = std::move(response);
        result.midpoint = verified->midpoint;
        result.radius = verified->radius;

        return result;
    }
};

Client::Client() : impl_(std::make_unique<Impl>()) {}
Client::~Client() = default;

QueryResult Client::query(
    const Server& server,
    int attempts,
    std::chrono::milliseconds timeout,
    const std::optional<QueryResult>& prev
) {
    return impl_->query_server(server, attempts, timeout, prev);
}

std::vector<QueryResult> Client::query_servers(
    const std::vector<Server>& servers,
    int attempts,
    std::chrono::milliseconds timeout
) {
    std::vector<QueryResult> results;
    results.reserve(servers.size());

    std::optional<QueryResult> prev;
    for (const auto& server : servers) {
        auto result = query(server, attempts, timeout, prev);
        if (result.is_success()) {
            prev = result;
        }
        results.push_back(std::move(result));
    }

    return results;
}

std::optional<MedianDeltaResult> calculate_median_delta(
    const std::vector<QueryResult>& results,
    std::chrono::system_clock::time_point reference_time,
    std::chrono::seconds radius_threshold
) {
    if (results.empty()) {
        return std::nullopt;
    }

    std::vector<std::chrono::milliseconds> deltas;
    std::chrono::milliseconds accumulated_delay{0};

    for (const auto& result : results) {
        accumulated_delay += result.network_delay;

        if (result.is_success() && result.radius <= radius_threshold) {
            auto time_delta = std::chrono::duration_cast<std::chrono::milliseconds>(
                result.midpoint - reference_time
            );
            deltas.push_back(time_delta - accumulated_delay);
        }
    }

    if (deltas.empty()) {
        return std::nullopt;
    }

    // Calculate median
    std::sort(deltas.begin(), deltas.end());

    std::chrono::milliseconds median;
    if (deltas.size() % 2 == 0) {
        median = (deltas[deltas.size() / 2 - 1] + deltas[deltas.size() / 2]) / 2;
    } else {
        median = deltas[deltas.size() / 2];
    }

    return MedianDeltaResult{median, deltas.size()};
}

std::string MalfeasanceReport::to_string() const {
    std::ostringstream oss;
    oss << "MALFEASANCE DETECTED:\n";
    oss << "  Server " << server_i_index << " (" << server_i_name << ")\n";
    oss << "    MIDP: " << std::chrono::duration_cast<std::chrono::seconds>(
        midpoint_i.time_since_epoch()).count() << "s\n";
    oss << "    RADI: " << radius_i.count() << "s\n";
    oss << "    Lower bound: " << std::chrono::duration_cast<std::chrono::seconds>(
        (midpoint_i - radius_i).time_since_epoch()).count() << "s\n";
    oss << "  Server " << server_j_index << " (" << server_j_name << ")\n";
    oss << "    MIDP: " << std::chrono::duration_cast<std::chrono::seconds>(
        midpoint_j.time_since_epoch()).count() << "s\n";
    oss << "    RADI: " << radius_j.count() << "s\n";
    oss << "    Upper bound: " << std::chrono::duration_cast<std::chrono::seconds>(
        (midpoint_j + radius_j).time_since_epoch()).count() << "s\n";
    oss << "  Violation: MIDP_i - RADI_i > MIDP_j + RADI_j\n";
    oss << "  (Earlier query's lower bound exceeds later query's upper bound)\n";
    return oss.str();
}

std::optional<MalfeasanceReport> validate_causal_ordering(
    const std::vector<QueryResult>& results
) {
    // Per RFC draft-ietf-ntp-roughtime 8.2:
    // For each pair (i, j) where i received before j,
    // must check: MIDP_i - RADI_i <= MIDP_j + RADI_j
    //
    // This ensures times are consistent with causal ordering.
    // If this check fails, at least one server is lying.

    for (size_t i = 0; i < results.size(); i++) {
        if (!results[i].is_success()) continue;

        for (size_t j = i + 1; j < results.size(); j++) {
            if (!results[j].is_success()) continue;

            auto lower_i = results[i].midpoint - results[i].radius;
            auto upper_j = results[j].midpoint + results[j].radius;

            if (lower_i > upper_j) {
                // Causal ordering violation detected!
                MalfeasanceReport report;
                report.server_i_index = i;
                report.server_j_index = j;
                report.server_i_name = results[i].server ? results[i].server->name : "unknown";
                report.server_j_name = results[j].server ? results[j].server->name : "unknown";
                report.midpoint_i = results[i].midpoint;
                report.midpoint_j = results[j].midpoint;
                report.radius_i = results[i].radius;
                report.radius_j = results[j].radius;
                report.response_i = results[i].response;
                report.response_j = results[j].response;

                LOG(ERROR) << "Causal ordering violation detected:";
                LOG(ERROR) << report.to_string();

                return report;
            }
        }
    }

    return std::nullopt;
}

TrustedTimeResult Client::query_for_trusted_time(
    const std::vector<Server>& servers,
    size_t min_servers,
    int attempts,
    std::chrono::milliseconds timeout,
    std::chrono::seconds radius_threshold,
    std::chrono::milliseconds max_network_delay
) {
    TrustedTimeResult result;
    result.total_queried = servers.size();  // Set to actual servers provided
    result.agreeing_servers = 0;

    if (servers.empty()) {
        result.total_queried = 0;
        result.error = "No servers provided";
        return result;
    }

    if (servers.size() < min_servers) {
        result.error = "Not enough servers: need at least " + std::to_string(min_servers) +
                      " but only " + std::to_string(servers.size()) + " provided";
        return result;
    }

    // RFC 8.2: Randomly select at least min_servers from the list
    std::vector<Server> selected_servers;
    if (servers.size() > min_servers) {
        LOG(INFO) << "Randomly selecting " << min_servers << " servers from " << servers.size();

        std::vector<size_t> indices(servers.size());
        std::iota(indices.begin(), indices.end(), 0);

        std::random_device rd;
        std::mt19937 gen(rd());
        std::shuffle(indices.begin(), indices.end(), gen);

        for (size_t i = 0; i < min_servers; i++) {
            selected_servers.push_back(servers[indices[i]]);
        }
    } else {
        // Use all servers if we don't have more than min_servers
        selected_servers = servers;
    }

    result.total_queried = selected_servers.size();

    // RFC 8.2: Retry if malfeasance detected (max 3 attempts)
    const int max_measurement_attempts = 3;
    for (int measurement_attempt = 0; measurement_attempt < max_measurement_attempts; measurement_attempt++) {
        if (measurement_attempt > 0) {
            LOG(WARNING) << "Retrying measurement after malfeasance (attempt "
                        << measurement_attempt + 1 << "/" << max_measurement_attempts << ")";

            // Re-select different servers for retry
            if (servers.size() > min_servers) {
                selected_servers.clear();
                std::vector<size_t> indices(servers.size());
                std::iota(indices.begin(), indices.end(), 0);

                std::random_device rd;
                std::mt19937 gen(rd());
                std::shuffle(indices.begin(), indices.end(), gen);

                for (size_t i = 0; i < min_servers; i++) {
                    selected_servers.push_back(servers[indices[i]]);
                }
            }
        }

        // Per RFC 8.2: Query servers twice in same order (repeated measurement)
        // This ensures all possible inconsistencies can be detected
        LOG(INFO) << "Performing repeated measurement sequence (2 passes)";

        // First pass
        auto results_pass1 = query_servers(selected_servers, attempts, timeout);

        // Validate causal ordering for first pass
        auto malfeasance1 = validate_causal_ordering(results_pass1);
        if (malfeasance1) {
            result.malfeasance = malfeasance1;
            result.error = "Causal ordering violation detected in first pass";
            result.all_results = results_pass1;
            LOG(WARNING) << "Malfeasance detected in pass 1, will retry if attempts remain";
            continue;  // Try again with different servers
        }

        // Second pass - query same servers in same order
        auto results_pass2 = query_servers(selected_servers, attempts, timeout);

        // Validate causal ordering for second pass
        auto malfeasance2 = validate_causal_ordering(results_pass2);
        if (malfeasance2) {
            result.malfeasance = malfeasance2;
            result.error = "Causal ordering violation detected in second pass";
            result.all_results = results_pass2;
            LOG(WARNING) << "Malfeasance detected in pass 2, will retry if attempts remain";
            continue;  // Try again with different servers
        }

        // Combine both passes for validation
        std::vector<QueryResult> combined_results;
        combined_results.reserve(results_pass1.size() + results_pass2.size());
        combined_results.insert(combined_results.end(), results_pass1.begin(), results_pass1.end());
        combined_results.insert(combined_results.end(), results_pass2.begin(), results_pass2.end());

        // Validate causal ordering across both passes
        auto malfeasance_combined = validate_causal_ordering(combined_results);
        if (malfeasance_combined) {
            result.malfeasance = malfeasance_combined;
            result.error = "Causal ordering violation detected across measurement passes";
            result.all_results = combined_results;
            LOG(WARNING) << "Cross-pass malfeasance detected, will retry if attempts remain";
            continue;  // Try again with different servers
        }

        LOG(INFO) << "Repeated measurement complete, no malfeasance detected";

        // Use second pass results for time calculation (more recent)
        result.all_results = results_pass2;

        // Filter successful results
        std::vector<QueryResult> successful;
        for (const auto& r : result.all_results) {
            if (r.is_success() && r.radius <= radius_threshold) {
                successful.push_back(r);
            }
        }

        if (successful.empty()) {
            result.error = "No servers responded successfully";
            LOG(WARNING) << "No successful responses, will retry if attempts remain";
            continue;
        }

        if (successful.size() < min_servers) {
            result.error = "Insufficient servers for trust: only " +
                          std::to_string(successful.size()) + " of " +
                          std::to_string(min_servers) + " required responded successfully";
            LOG(WARNING) << result.error << ", will retry if attempts remain";
            continue;
        }

        // RFC 8.2: Validate network delay is reasonable
        bool excessive_delay = false;
        for (const auto& r : successful) {
            if (r.network_delay > max_network_delay) {
                LOG(WARNING) << "Server " << (r.server ? r.server->name : "unknown")
                            << " has excessive network delay: " << r.network_delay.count()
                            << "ms (max: " << max_network_delay.count() << "ms)";
                excessive_delay = true;
            }
        }

        if (excessive_delay) {
            result.error = "Network delay exceeds acceptable threshold";
            LOG(WARNING) << result.error << ", will retry if attempts remain";
            continue;
        }

        // Calculate median time
        auto reference = std::chrono::system_clock::now();
        auto median_result = calculate_median_delta(result.all_results, reference, radius_threshold);

        if (!median_result) {
            result.error = "Failed to calculate median time";
            LOG(WARNING) << result.error << ", will retry if attempts remain";
            continue;
        }

        result.agreeing_servers = median_result->valid_count;
        result.time = reference + median_result->delta;

        // Calculate uncertainty as the maximum radius among agreeing servers
        std::chrono::seconds max_radius{0};
        for (const auto& r : successful) {
            if (r.radius > max_radius) {
                max_radius = r.radius;
            }
        }
        result.uncertainty = max_radius;

        // Success! Clear any error and return
        result.error.clear();
        result.malfeasance.reset();
        LOG(INFO) << "Trusted time established from " << result.agreeing_servers << " servers";
        return result;
    }

    // All retry attempts exhausted
    if (result.error.empty()) {
        result.error = "Failed to establish trusted time after " +
                      std::to_string(max_measurement_attempts) + " attempts";
    }
    LOG(ERROR) << "All measurement attempts exhausted: " << result.error;
    return result;
}

} // namespace roughtime

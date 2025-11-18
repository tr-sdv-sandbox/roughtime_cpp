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

TrustedTimeResult Client::query_for_trusted_time(
    const std::vector<Server>& servers,
    size_t min_servers,
    int attempts,
    std::chrono::milliseconds timeout,
    std::chrono::seconds radius_threshold
) {
    TrustedTimeResult result;
    result.total_queried = servers.size();
    result.agreeing_servers = 0;

    if (servers.empty()) {
        result.error = "No servers provided";
        return result;
    }

    if (servers.size() < min_servers) {
        result.error = "Not enough servers: need at least " + std::to_string(min_servers) +
                      " but only " + std::to_string(servers.size()) + " provided";
        return result;
    }

    // Query all servers
    result.all_results = query_servers(servers, attempts, timeout);

    // Filter successful results
    std::vector<QueryResult> successful;
    for (const auto& r : result.all_results) {
        if (r.is_success() && r.radius <= radius_threshold) {
            successful.push_back(r);
        }
    }

    if (successful.empty()) {
        result.error = "No servers responded successfully";
        return result;
    }

    if (successful.size() < min_servers) {
        result.error = "Insufficient servers for trust: only " +
                      std::to_string(successful.size()) + " of " +
                      std::to_string(min_servers) + " required responded successfully";
        return result;
    }

    // Calculate median time
    auto reference = std::chrono::system_clock::now();
    auto median_result = calculate_median_delta(result.all_results, reference, radius_threshold);

    if (!median_result) {
        result.error = "Failed to calculate median time";
        return result;
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

    return result;
}

} // namespace roughtime

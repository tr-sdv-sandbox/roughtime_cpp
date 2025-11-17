// Copyright 2024
// SPDX-License-Identifier: Apache-2.0
//
// Rate Limiter for DoS Protection
// Implements token bucket algorithm per IP address

#pragma once

#include <string>
#include <unordered_map>
#include <chrono>
#include <mutex>
#include <cstdint>

namespace roughtime {
namespace server {

/**
 * @brief Configuration for rate limiting
 */
struct RateLimitConfig {
    bool enabled = true;  // Enable/disable rate limiting
    size_t max_requests_per_window = 100;  // Maximum requests per time window
    std::chrono::seconds window_duration{10};  // Time window duration
    size_t max_tracked_ips = 10000;  // Maximum number of IPs to track
};

/**
 * @brief Per-client rate limiting state
 */
struct ClientState {
    size_t tokens;  // Remaining tokens
    std::chrono::steady_clock::time_point last_refill;  // Last refill time

    ClientState(size_t initial_tokens)
        : tokens(initial_tokens)
        , last_refill(std::chrono::steady_clock::now())
    {}
};

/**
 * @brief Thread-safe rate limiter using token bucket algorithm
 *
 * Each IP address has a bucket of tokens that refills over time.
 * Each request consumes one token. If no tokens available, request is rate limited.
 */
class RateLimiter {
public:
    /**
     * @brief Construct rate limiter with configuration
     * @param config Rate limiting configuration
     */
    explicit RateLimiter(const RateLimitConfig& config = RateLimitConfig())
        : config_(config)
    {}

    /**
     * @brief Check if a request from an IP address should be allowed
     * @param client_ip IP address of the client
     * @return true if request should be allowed, false if rate limited
     */
    bool allow_request(const std::string& client_ip) {
        std::lock_guard<std::mutex> lock(mutex_);

        auto now = std::chrono::steady_clock::now();

        // Find or create client state
        auto it = clients_.find(client_ip);
        if (it == clients_.end()) {
            // New client - check if we can track more IPs
            if (clients_.size() >= config_.max_tracked_ips) {
                // Evict oldest entry using simple LRU approximation
                cleanup_old_entries(now);

                // If still full, allow request but don't track (fail open for new clients)
                if (clients_.size() >= config_.max_tracked_ips) {
                    return true;
                }
            }

            // Create new entry with full bucket
            it = clients_.emplace(client_ip, ClientState(config_.max_requests_per_window)).first;
        }

        auto& state = it->second;

        // Refill tokens based on elapsed time
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - state.last_refill);
        if (elapsed >= config_.window_duration) {
            // Full refill after window duration
            state.tokens = config_.max_requests_per_window;
            state.last_refill = now;
        } else if (elapsed.count() > 0) {
            // Partial refill proportional to elapsed time
            double refill_rate = static_cast<double>(config_.max_requests_per_window) /
                                static_cast<double>(config_.window_duration.count());
            size_t tokens_to_add = static_cast<size_t>(refill_rate * static_cast<double>(elapsed.count()));

            if (tokens_to_add > 0) {
                state.tokens = std::min(state.tokens + tokens_to_add, config_.max_requests_per_window);
                state.last_refill = now;
            }
        }

        // Check if request can be allowed
        if (state.tokens > 0) {
            state.tokens--;
            return true;
        }

        return false;  // Rate limited
    }

    /**
     * @brief Reset rate limiting for a specific IP
     * @param client_ip IP address to reset
     */
    void reset(const std::string& client_ip) {
        std::lock_guard<std::mutex> lock(mutex_);
        clients_.erase(client_ip);
    }

    /**
     * @brief Clear all rate limiting state
     */
    void clear_all() {
        std::lock_guard<std::mutex> lock(mutex_);
        clients_.clear();
    }

    /**
     * @brief Get current statistics
     * @return Number of tracked IP addresses
     */
    size_t tracked_clients() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return clients_.size();
    }

private:
    /**
     * @brief Remove old entries that haven't been active recently
     * @param now Current timestamp
     */
    void cleanup_old_entries(std::chrono::steady_clock::time_point now) {
        // Remove entries that haven't been active for 2x window duration
        auto timeout = config_.window_duration * 2;

        for (auto it = clients_.begin(); it != clients_.end();) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                now - it->second.last_refill
            );

            if (elapsed > timeout) {
                it = clients_.erase(it);
            } else {
                ++it;
            }
        }
    }

    RateLimitConfig config_;
    mutable std::mutex mutex_;  // Protects clients_ map
    std::unordered_map<std::string, ClientState> clients_;
};

} // namespace server
} // namespace roughtime

// Copyright 2024
// SPDX-License-Identifier: Apache-2.0
//
// Input Validation Constants and Functions
// Provides validation for server configuration, protocol messages, and client requests

#pragma once

#include <roughtime/protocol.h>
#include <roughtime/server.h>
#include <string>
#include <chrono>
#include <optional>
#include <vector>

namespace roughtime {
namespace validation {

// ============================================================================
// Protocol Constants
// ============================================================================

// Message size limits (for DoS protection)
constexpr size_t MAX_REQUEST_SIZE = 2048;        // Maximum client request size
constexpr size_t MAX_RESPONSE_SIZE = 4096;       // Maximum server response size
constexpr size_t MAX_BATCH_SIZE = 64;            // Maximum requests in batch

// Nonce validation
constexpr size_t IETF_NONCE_SIZE = 32;           // IETF Roughtime nonce size
constexpr size_t GOOGLE_NONCE_SIZE = 64;         // Google Roughtime nonce size
constexpr size_t MIN_NONCE_SIZE = 32;
constexpr size_t MAX_NONCE_SIZE_LIMIT = 64;

// Time bounds (for sanity checking)
constexpr int64_t MIN_VALID_TIMESTAMP = 946684800;         // 2000-01-01 00:00:00 UTC
constexpr int64_t MAX_VALID_TIMESTAMP = 4102444800;        // 2100-01-01 00:00:00 UTC
constexpr int64_t MAX_RADIUS_SECONDS = 86400;              // 24 hours maximum radius
constexpr int64_t MAX_CERT_VALIDITY_HOURS = 8760;          // 1 year maximum

// Network limits
constexpr uint16_t MIN_PORT = 1024;              // Minimum non-privileged port
constexpr uint16_t MAX_PORT = 65535;             // Maximum valid port
constexpr int MAX_RETRIES = 10;                  // Maximum retry attempts
constexpr int64_t MAX_TIMEOUT_MS = 60000;        // 60 seconds maximum timeout

// Key size validation
constexpr size_t ED25519_PUBKEY_SIZE = 32;
constexpr size_t ED25519_PRIVKEY_SIZE = 64;
constexpr size_t ED25519_SIG_SIZE = 64;

// ============================================================================
// Validation Result
// ============================================================================

struct ValidationResult {
    bool valid;
    std::string error_message;

    static ValidationResult success() {
        return {true, ""};
    }

    static ValidationResult failure(const std::string& msg) {
        return {false, msg};
    }

    explicit operator bool() const { return valid; }
};

// ============================================================================
// Server Configuration Validation
// ============================================================================

/**
 * @brief Validate server configuration
 * @param config Server configuration to validate
 * @return Validation result with error message if invalid
 */
inline ValidationResult validate_server_config(const server::ServerConfig& config) {
    // Validate port
    if (config.port < MIN_PORT || config.port > MAX_PORT) {
        return ValidationResult::failure(
            "Invalid port: " + std::to_string(config.port) +
            " (must be between " + std::to_string(MIN_PORT) +
            " and " + std::to_string(MAX_PORT) + ")"
        );
    }

    // Validate address (basic check for non-empty)
    if (config.address.empty()) {
        return ValidationResult::failure("Address cannot be empty");
    }

    // Validate radius (should be reasonable)
    if (config.radius.count() < 0) {
        return ValidationResult::failure("Radius cannot be negative");
    }
    if (config.radius.count() > MAX_RADIUS_SECONDS) {
        return ValidationResult::failure(
            "Radius too large: " + std::to_string(config.radius.count()) +
            "s (maximum: " + std::to_string(MAX_RADIUS_SECONDS) + "s)"
        );
    }

    // Validate certificate validity
    if (config.cert_validity.count() <= 0) {
        return ValidationResult::failure("Certificate validity must be positive");
    }
    if (config.cert_validity.count() > MAX_CERT_VALIDITY_HOURS) {
        return ValidationResult::failure(
            "Certificate validity too long: " + std::to_string(config.cert_validity.count()) +
            "h (maximum: " + std::to_string(MAX_CERT_VALIDITY_HOURS) + "h)"
        );
    }

    return ValidationResult::success();
}

// ============================================================================
// Protocol Message Validation
// ============================================================================

/**
 * @brief Validate request size
 * @param request_size Size of the request in bytes
 * @return Validation result
 */
inline ValidationResult validate_request_size(size_t request_size) {
    if (request_size < MIN_REQUEST_SIZE) {
        return ValidationResult::failure(
            "Request too small: " + std::to_string(request_size) +
            " bytes (minimum: " + std::to_string(MIN_REQUEST_SIZE) + ")"
        );
    }
    if (request_size > MAX_REQUEST_SIZE) {
        return ValidationResult::failure(
            "Request too large: " + std::to_string(request_size) +
            " bytes (maximum: " + std::to_string(MAX_REQUEST_SIZE) + ")"
        );
    }
    return ValidationResult::success();
}

/**
 * @brief Validate response size
 * @param response_size Size of the response in bytes
 * @return Validation result
 */
inline ValidationResult validate_response_size(size_t response_size) {
    if (response_size > MAX_RESPONSE_SIZE) {
        return ValidationResult::failure(
            "Response too large: " + std::to_string(response_size) +
            " bytes (maximum: " + std::to_string(MAX_RESPONSE_SIZE) + ")"
        );
    }
    return ValidationResult::success();
}

/**
 * @brief Validate nonce size
 * @param nonce_size Size of the nonce in bytes
 * @param version_ietf Whether this is IETF Roughtime (vs Google)
 * @return Validation result
 */
inline ValidationResult validate_nonce_size(size_t nonce_size, bool version_ietf) {
    size_t expected_size = version_ietf ? IETF_NONCE_SIZE : GOOGLE_NONCE_SIZE;

    if (nonce_size != expected_size) {
        return ValidationResult::failure(
            "Invalid nonce size: " + std::to_string(nonce_size) +
            " bytes (expected: " + std::to_string(expected_size) +
            " for " + (version_ietf ? "IETF" : "Google") + " Roughtime)"
        );
    }

    return ValidationResult::success();
}

/**
 * @brief Validate batch size
 * @param batch_size Number of requests in batch
 * @return Validation result
 */
inline ValidationResult validate_batch_size(size_t batch_size) {
    if (batch_size == 0) {
        return ValidationResult::failure("Batch cannot be empty");
    }
    if (batch_size > MAX_BATCH_SIZE) {
        return ValidationResult::failure(
            "Batch too large: " + std::to_string(batch_size) +
            " requests (maximum: " + std::to_string(MAX_BATCH_SIZE) + ")"
        );
    }
    return ValidationResult::success();
}

// ============================================================================
// Time Validation
// ============================================================================

/**
 * @brief Validate timestamp is within reasonable bounds
 * @param timestamp Unix timestamp in seconds
 * @return Validation result
 */
inline ValidationResult validate_timestamp(int64_t timestamp) {
    if (timestamp < MIN_VALID_TIMESTAMP) {
        return ValidationResult::failure(
            "Timestamp too old: " + std::to_string(timestamp) +
            " (minimum: " + std::to_string(MIN_VALID_TIMESTAMP) + ")"
        );
    }
    if (timestamp > MAX_VALID_TIMESTAMP) {
        return ValidationResult::failure(
            "Timestamp too far in future: " + std::to_string(timestamp) +
            " (maximum: " + std::to_string(MAX_VALID_TIMESTAMP) + ")"
        );
    }
    return ValidationResult::success();
}

/**
 * @brief Validate time range for certificate
 * @param min_time Certificate start time
 * @param max_time Certificate end time
 * @return Validation result
 */
inline ValidationResult validate_time_range(
    std::chrono::system_clock::time_point min_time,
    std::chrono::system_clock::time_point max_time
) {
    if (min_time >= max_time) {
        return ValidationResult::failure("Invalid time range: min_time must be less than max_time");
    }

    auto min_ts = std::chrono::duration_cast<std::chrono::seconds>(
        min_time.time_since_epoch()
    ).count();
    auto max_ts = std::chrono::duration_cast<std::chrono::seconds>(
        max_time.time_since_epoch()
    ).count();

    auto min_result = validate_timestamp(min_ts);
    if (!min_result) {
        return min_result;
    }

    auto max_result = validate_timestamp(max_ts);
    if (!max_result) {
        return max_result;
    }

    // Check validity duration is reasonable
    auto duration_hours = std::chrono::duration_cast<std::chrono::hours>(
        max_time - min_time
    ).count();

    if (duration_hours > MAX_CERT_VALIDITY_HOURS) {
        return ValidationResult::failure(
            "Certificate validity too long: " + std::to_string(duration_hours) +
            "h (maximum: " + std::to_string(MAX_CERT_VALIDITY_HOURS) + "h)"
        );
    }

    return ValidationResult::success();
}

// ============================================================================
// Client Request Validation
// ============================================================================

/**
 * @brief Validate retry count
 * @param retries Number of retry attempts
 * @return Validation result
 */
inline ValidationResult validate_retries(int retries) {
    if (retries < 0) {
        return ValidationResult::failure("Retry count cannot be negative");
    }
    if (retries > MAX_RETRIES) {
        return ValidationResult::failure(
            "Too many retries: " + std::to_string(retries) +
            " (maximum: " + std::to_string(MAX_RETRIES) + ")"
        );
    }
    return ValidationResult::success();
}

/**
 * @brief Validate timeout duration
 * @param timeout_ms Timeout in milliseconds
 * @return Validation result
 */
inline ValidationResult validate_timeout(int64_t timeout_ms) {
    if (timeout_ms <= 0) {
        return ValidationResult::failure("Timeout must be positive");
    }
    if (timeout_ms > MAX_TIMEOUT_MS) {
        return ValidationResult::failure(
            "Timeout too long: " + std::to_string(timeout_ms) +
            "ms (maximum: " + std::to_string(MAX_TIMEOUT_MS) + "ms)"
        );
    }
    return ValidationResult::success();
}

/**
 * @brief Validate version list is not empty
 * @param versions List of protocol versions
 * @return Validation result
 */
inline ValidationResult validate_versions(const std::vector<Version>& versions) {
    if (versions.empty()) {
        return ValidationResult::failure("Version list cannot be empty");
    }
    return ValidationResult::success();
}

} // namespace validation
} // namespace roughtime

// Copyright 2024
// SPDX-License-Identifier: Apache-2.0
//
// Cryptographic operations for Roughtime

#pragma once

#include "config.h"
#include <array>
#include <vector>
#include <cstdint>

namespace roughtime {
namespace crypto {

constexpr size_t ED25519_PRIVATE_KEY_SIZE = 64;
constexpr size_t ED25519_SIGNATURE_SIZE = 64;
constexpr size_t SHA512256_SIZE = 32;  // SHA-512/256 produces 32 bytes
constexpr size_t SHA512_SIZE = 64;

// SHA-512/256 hashing (used by IETF Roughtime)
std::array<uint8_t, SHA512256_SIZE> sha512256(const std::vector<uint8_t>& data);
std::array<uint8_t, SHA512256_SIZE> sha512256(const uint8_t* data, size_t len);

// SHA-512 hashing
std::array<uint8_t, SHA512_SIZE> sha512(const std::vector<uint8_t>& data);
std::array<uint8_t, SHA512_SIZE> sha512(const uint8_t* data, size_t len);

// SHA-512 with multiple inputs
std::array<uint8_t, SHA512_SIZE> sha512_multi(
    const std::vector<std::vector<uint8_t>>& inputs
);

// Ed25519 signature verification
bool ed25519_verify(
    const std::array<uint8_t, ED25519_PUBLIC_KEY_SIZE>& public_key,
    const std::vector<uint8_t>& message,
    const std::array<uint8_t, ED25519_SIGNATURE_SIZE>& signature
);

// Random bytes generation
void random_bytes(uint8_t* buffer, size_t len);
std::vector<uint8_t> random_bytes(size_t len);

// Merkle tree operations
class MerkleTree {
public:
    explicit MerkleTree(size_t nonce_size, const std::vector<std::vector<uint8_t>>& nonces);

    std::vector<uint8_t> root() const;
    std::vector<std::vector<uint8_t>> path(size_t index) const;
    size_t levels() const noexcept { return values_.size(); }

    // Public static hash functions for use in protocol verification
    // hash_size should be 32 (SHA256_SIZE) for IETF or 64 (SHA512_SIZE) for Google
    static std::vector<uint8_t> hash_leaf(const std::vector<uint8_t>& nonce, size_t hash_size);
    static std::vector<uint8_t> hash_node(
        const uint8_t* left,
        const uint8_t* right,
        size_t hash_size
    );

private:
    size_t nonce_size_;
    std::vector<std::vector<std::array<uint8_t, SHA512_SIZE>>> values_;
};

} // namespace crypto
} // namespace roughtime

// Copyright 2024
// SPDX-License-Identifier: Apache-2.0
//
// Shared Test Utilities
// Common helper functions for Ed25519 operations in tests

#pragma once

#include <roughtime/openssl_wrappers.h>
#include <openssl/evp.h>
#include <array>
#include <stdexcept>
#include <algorithm>

namespace roughtime {
namespace test {

/**
 * @brief Generate Ed25519 keypair for testing
 * @param public_key Output buffer for 32-byte public key
 * @param private_key Output buffer for 64-byte private key (32-byte seed + 32-byte public key)
 */
inline void ed25519_keypair(std::array<uint8_t, 32>& public_key, std::array<uint8_t, 64>& private_key) {
    crypto::EVPPKeyContext ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr));
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_PKEY_CTX");
    }

    if (EVP_PKEY_keygen_init(ctx.get()) != 1) {
        throw std::runtime_error("Failed to initialize keygen");
    }

    EVP_PKEY* pkey_raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &pkey_raw) != 1) {
        throw std::runtime_error("Failed to generate keypair");
    }
    crypto::EVPPKey pkey(pkey_raw);

    size_t pub_len = 32;
    if (EVP_PKEY_get_raw_public_key(pkey.get(), public_key.data(), &pub_len) != 1) {
        throw std::runtime_error("Failed to extract public key");
    }

    size_t priv_len = 32;
    if (EVP_PKEY_get_raw_private_key(pkey.get(), private_key.data(), &priv_len) != 1) {
        throw std::runtime_error("Failed to extract private key");
    }

    // OpenSSL stores only 32-byte seed for Ed25519 private key
    // For compatibility with existing code that expects 64 bytes, we duplicate:
    // First 32 bytes = private key seed, last 32 bytes = public key
    std::copy(public_key.begin(), public_key.end(), private_key.begin() + 32);
}

/**
 * @brief Sign message with Ed25519 for testing
 * @param signature Output buffer for 64-byte signature
 * @param message Message to sign
 * @param message_len Length of message
 * @param private_key 32-byte (or 64-byte) private key
 */
inline void ed25519_sign(
    std::array<uint8_t, 64>& signature,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* private_key
) {
    crypto::EVPPKey pkey(EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, private_key, 32
    ));
    if (!pkey) {
        throw std::runtime_error("Failed to create EVP_PKEY from private key");
    }

    crypto::EVPMDContext ctx;

    if (EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get()) != 1) {
        throw std::runtime_error("Failed to initialize signing");
    }

    size_t sig_len = signature.size();
    if (EVP_DigestSign(ctx.get(), signature.data(), &sig_len, message, message_len) != 1) {
        throw std::runtime_error("Failed to sign message");
    }
}

} // namespace test
} // namespace roughtime

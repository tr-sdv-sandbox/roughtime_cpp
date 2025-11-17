// Copyright 2024
// SPDX-License-Identifier: Apache-2.0

#include "roughtime/crypto.h"
#include "roughtime/openssl_wrappers.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <cstring>
#include <stdexcept>

namespace roughtime {
namespace crypto {

std::array<uint8_t, SHA512256_SIZE> sha512256(const std::vector<uint8_t>& data) {
    return sha512256(data.data(), data.size());
}

std::array<uint8_t, SHA512256_SIZE> sha512256(const uint8_t* data, size_t len) {
    // Use OpenSSL's proper SHA-512/256 (as per FIPS 180-4)
    std::array<uint8_t, SHA512256_SIZE> hash;
    EVPMDContext ctx;

    if (EVP_DigestInit_ex(ctx.get(), EVP_sha512_256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx.get(), data, len) != 1 ||
        EVP_DigestFinal_ex(ctx.get(), hash.data(), nullptr) != 1) {
        throw std::runtime_error("SHA-512/256 hashing failed");
    }

    return hash;
}

std::array<uint8_t, SHA512_SIZE> sha512(const std::vector<uint8_t>& data) {
    return sha512(data.data(), data.size());
}

std::array<uint8_t, SHA512_SIZE> sha512(const uint8_t* data, size_t len) {
    std::array<uint8_t, SHA512_SIZE> hash;
    EVPMDContext ctx;

    if (EVP_DigestInit_ex(ctx.get(), EVP_sha512(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx.get(), data, len) != 1 ||
        EVP_DigestFinal_ex(ctx.get(), hash.data(), nullptr) != 1) {
        throw std::runtime_error("SHA-512 hashing failed");
    }

    return hash;
}

std::array<uint8_t, SHA512_SIZE> sha512_multi(
    const std::vector<std::vector<uint8_t>>& inputs
) {
    std::array<uint8_t, SHA512_SIZE> hash;
    EVPMDContext ctx;

    if (EVP_DigestInit_ex(ctx.get(), EVP_sha512(), nullptr) != 1) {
        throw std::runtime_error("SHA-512 init failed");
    }

    for (const auto& input : inputs) {
        if (EVP_DigestUpdate(ctx.get(), input.data(), input.size()) != 1) {
            throw std::runtime_error("SHA-512 update failed");
        }
    }

    if (EVP_DigestFinal_ex(ctx.get(), hash.data(), nullptr) != 1) {
        throw std::runtime_error("SHA-512 final failed");
    }

    return hash;
}

bool ed25519_verify(
    const std::array<uint8_t, ED25519_PUBLIC_KEY_SIZE>& public_key,
    const std::vector<uint8_t>& message,
    const std::array<uint8_t, ED25519_SIGNATURE_SIZE>& signature
) {
    // Create EVP_PKEY from raw Ed25519 public key
    EVPPKey pkey(EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519,
        nullptr,
        public_key.data(),
        ED25519_PUBLIC_KEY_SIZE
    ));
    if (!pkey) {
        return false;
    }

    // Create verification context
    EVPMDContext ctx;

    // Initialize verification (Ed25519 doesn't use a digest algorithm)
    if (EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get()) != 1) {
        return false;
    }

    // Verify the signature
    int result = EVP_DigestVerify(ctx.get(), signature.data(), signature.size(),
                                   message.data(), message.size());

    return result == 1;
}

void random_bytes(uint8_t* buffer, size_t len) {
    // Check for integer overflow before casting to int
    if (len > INT_MAX) {
        throw std::invalid_argument("Random bytes length too large");
    }
    if (RAND_bytes(buffer, static_cast<int>(len)) != 1) {
        throw std::runtime_error("Failed to generate random bytes");
    }
}

std::vector<uint8_t> random_bytes(size_t len) {
    std::vector<uint8_t> result(len);
    random_bytes(result.data(), len);
    return result;
}

// Merkle Tree implementation
std::vector<uint8_t> MerkleTree::hash_leaf(const std::vector<uint8_t>& nonce, size_t hash_size) {
    std::vector<uint8_t> input;
    input.push_back(0); // leaf tweak
    input.insert(input.end(), nonce.begin(), nonce.end());

    if (hash_size == SHA512256_SIZE) {
        // IETF Roughtime: SHA-512/256
        auto hash = sha512256(input);
        return std::vector<uint8_t>(hash.begin(), hash.end());
    } else {
        // Google Roughtime: SHA-512
        auto hash = sha512(input);
        return std::vector<uint8_t>(hash.begin(), hash.end());
    }
}

std::vector<uint8_t> MerkleTree::hash_node(
    const uint8_t* left,
    const uint8_t* right,
    size_t hash_size
) {
    std::vector<uint8_t> input;
    input.push_back(1); // node tweak
    input.insert(input.end(), left, left + hash_size);
    input.insert(input.end(), right, right + hash_size);

    if (hash_size == SHA512256_SIZE) {
        // IETF Roughtime: SHA-512/256
        auto hash = sha512256(input);
        return std::vector<uint8_t>(hash.begin(), hash.end());
    } else {
        // Google Roughtime: SHA-512
        auto hash = sha512(input);
        return std::vector<uint8_t>(hash.begin(), hash.end());
    }
}

MerkleTree::MerkleTree(size_t nonce_size, const std::vector<std::vector<uint8_t>>& nonces)
    : nonce_size_(nonce_size)
{
    if (nonces.empty()) {
        throw std::invalid_argument("Cannot create Merkle tree from empty nonce list");
    }

    // Determine hash size based on nonce size
    // IETF: nonce_size=32, hash_size=32 (SHA-256)
    // Google: nonce_size=64, hash_size=64 (SHA-512)
    size_t hash_size = nonce_size;

    // Calculate number of levels
    size_t levels = 1;
    size_t width = nonces.size();
    while (width > 1) {
        width = (width + 1) / 2;
        levels++;
    }

    values_.reserve(levels);

    // Create leaf level
    size_t leaf_count = ((nonces.size() + 1) / 2) * 2; // Round up to even number
    std::vector<std::array<uint8_t, SHA512_SIZE>> leaves(leaf_count);

    for (size_t i = 0; i < nonces.size(); i++) {
        auto leaf_hash = hash_leaf(nonces[i], hash_size);
        std::copy(leaf_hash.begin(), leaf_hash.end(), leaves[i].begin());
    }

    // Fill extra leaves with existing leaf to simplify analysis
    for (size_t i = nonces.size(); i < leaf_count; i++) {
        leaves[i] = leaves[0];
    }

    values_.push_back(std::move(leaves));

    // Build upper levels
    for (size_t level = 1; level < levels; level++) {
        const auto& last_level = values_[level - 1];
        size_t level_width = last_level.size() / 2;
        if (level_width % 2 == 1) {
            level_width++;
        }

        std::vector<std::array<uint8_t, SHA512_SIZE>> current_level(level_width);

        for (size_t j = 0; j < last_level.size() / 2; j++) {
            auto node_hash = hash_node(
                last_level[j * 2].data(),
                last_level[j * 2 + 1].data(),
                hash_size
            );
            std::copy(node_hash.begin(), node_hash.end(), current_level[j].begin());
        }

        // Fill extra node if needed
        if (last_level.size() / 2 < level_width) {
            current_level[last_level.size() / 2] = current_level[0];
        }

        values_.push_back(std::move(current_level));
    }
}

std::vector<uint8_t> MerkleTree::root() const {
    const auto& root_hash = values_.back()[0];
    return std::vector<uint8_t>(root_hash.begin(), root_hash.begin() + nonce_size_);
}

std::vector<std::vector<uint8_t>> MerkleTree::path(size_t index) const {
    std::vector<std::vector<uint8_t>> path;
    path.reserve(values_.size() - 1);

    for (size_t level = 0; level < values_.size() - 1; level++) {
        size_t sibling_index = (index % 2 == 1) ? index - 1 : index + 1;
        const auto& sibling_hash = values_[level][sibling_index];
        path.emplace_back(sibling_hash.begin(), sibling_hash.begin() + nonce_size_);
        index /= 2;
    }

    return path;
}

} // namespace crypto
} // namespace roughtime

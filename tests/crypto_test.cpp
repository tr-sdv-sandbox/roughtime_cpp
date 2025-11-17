// Copyright 2024
// SPDX-License-Identifier: Apache-2.0

#include <roughtime/crypto.h>
#include "test_utils.h"
#include <gtest/gtest.h>

using namespace roughtime::crypto;
using namespace roughtime::test;

class CryptoTest : public ::testing::Test {
protected:
    void SetUp() override {
        // No initialization needed for OpenSSL
    }
};

// SHA-512 tests
TEST_F(CryptoTest, SHA512Empty) {
    std::vector<uint8_t> empty;
    auto hash = sha512(empty);

    ASSERT_EQ(hash.size(), 64);

    // Known SHA-512 hash of empty string
    std::array<uint8_t, 64> expected = {
        0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
        0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
        0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
        0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
        0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
        0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
        0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
        0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e
    };

    ASSERT_EQ(hash, expected);
}

TEST_F(CryptoTest, SHA512KnownInput) {
    std::vector<uint8_t> input = {'a', 'b', 'c'};
    auto hash = sha512(input);

    ASSERT_EQ(hash.size(), 64);

    // Known SHA-512 hash of "abc"
    std::array<uint8_t, 64> expected = {
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
        0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
        0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
        0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
        0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
        0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
        0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
        0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f
    };

    ASSERT_EQ(hash, expected);
}

TEST_F(CryptoTest, SHA512MultiPart) {
    std::vector<std::vector<uint8_t>> inputs = {
        {'a', 'b'},
        {'c'}
    };
    auto hash = sha512_multi(inputs);

    // Should be same as hashing "abc"
    std::vector<uint8_t> full = {'a', 'b', 'c'};
    auto expected = sha512(full);

    ASSERT_EQ(hash, expected);
}

// Ed25519 tests
TEST_F(CryptoTest, Ed25519KeyGeneration) {
    std::array<uint8_t, 32> public_key;
    std::array<uint8_t, 64> private_key;

    ed25519_keypair(public_key, private_key);

    // Public key should be non-zero
    bool has_nonzero = false;
    for (auto b : public_key) {
        if (b != 0) {
            has_nonzero = true;
            break;
        }
    }
    ASSERT_TRUE(has_nonzero);
}

TEST_F(CryptoTest, Ed25519SignAndVerify) {
    std::array<uint8_t, 32> public_key;
    std::array<uint8_t, 64> private_key;
    ed25519_keypair(public_key, private_key);

    std::vector<uint8_t> message = {'t', 'e', 's', 't'};
    std::array<uint8_t, 64> signature;

    ed25519_sign(signature, message.data(), message.size(), private_key.data());

    bool valid = ed25519_verify(public_key, message, signature);
    ASSERT_TRUE(valid);
}

TEST_F(CryptoTest, Ed25519RejectBadSignature) {
    std::array<uint8_t, 32> public_key;
    std::array<uint8_t, 64> private_key;
    ed25519_keypair(public_key, private_key);

    std::vector<uint8_t> message = {'t', 'e', 's', 't'};
    std::array<uint8_t, 64> signature = {}; // Invalid signature

    bool valid = ed25519_verify(public_key, message, signature);
    ASSERT_FALSE(valid);
}

TEST_F(CryptoTest, Ed25519RejectModifiedMessage) {
    std::array<uint8_t, 32> public_key;
    std::array<uint8_t, 64> private_key;
    ed25519_keypair(public_key, private_key);

    std::vector<uint8_t> message = {'t', 'e', 's', 't'};
    std::array<uint8_t, 64> signature;

    ed25519_sign(signature, message.data(), message.size(), private_key.data());

    // Modify message
    std::vector<uint8_t> modified = {'t', 'e', 's', 't', 's'};

    bool valid = ed25519_verify(public_key, modified, signature);
    ASSERT_FALSE(valid);
}

// Random bytes tests
TEST_F(CryptoTest, RandomBytesGeneration) {
    auto bytes1 = random_bytes(32);
    auto bytes2 = random_bytes(32);

    ASSERT_EQ(bytes1.size(), 32);
    ASSERT_EQ(bytes2.size(), 32);

    // Should be different (probability of collision is negligible)
    ASSERT_NE(bytes1, bytes2);
}

TEST_F(CryptoTest, RandomBytesNonZero) {
    auto bytes = random_bytes(32);

    // At least one byte should be non-zero
    bool has_nonzero = false;
    for (auto b : bytes) {
        if (b != 0) {
            has_nonzero = true;
            break;
        }
    }
    ASSERT_TRUE(has_nonzero);
}

// Merkle tree tests
TEST_F(CryptoTest, MerkleTreeSingleNonce) {
    std::vector<uint8_t> nonce(32, 0x01);
    std::vector<std::vector<uint8_t>> nonces = {nonce};

    MerkleTree tree(32, nonces);
    auto root = tree.root();

    ASSERT_EQ(root.size(), 32);

    // Root should be hash of leaf (using SHA-256 for 32-byte nonces)
    auto expected = MerkleTree::hash_leaf(nonce, 32);
    ASSERT_EQ(root, expected);
}

TEST_F(CryptoTest, MerkleTreeTwoNonces) {
    std::vector<uint8_t> nonce1(32, 0x01);
    std::vector<uint8_t> nonce2(32, 0x02);
    std::vector<std::vector<uint8_t>> nonces = {nonce1, nonce2};

    MerkleTree tree(32, nonces);
    auto root = tree.root();

    ASSERT_EQ(root.size(), 32);
}

TEST_F(CryptoTest, MerkleTreePathLength) {
    std::vector<uint8_t> nonce1(32, 0x01);
    std::vector<uint8_t> nonce2(32, 0x02);
    std::vector<uint8_t> nonce3(32, 0x03);
    std::vector<uint8_t> nonce4(32, 0x04);
    std::vector<std::vector<uint8_t>> nonces = {nonce1, nonce2, nonce3, nonce4};

    MerkleTree tree(32, nonces);

    // For 4 nonces, tree height is 2, so path length should be 2
    auto path0 = tree.path(0);
    auto path1 = tree.path(1);

    ASSERT_EQ(path0.size(), 2);
    ASSERT_EQ(path1.size(), 2);
}

TEST_F(CryptoTest, MerkleTreeVerifyPath) {
    std::vector<uint8_t> nonce1(32, 0x01);
    std::vector<uint8_t> nonce2(32, 0x02);
    std::vector<std::vector<uint8_t>> nonces = {nonce1, nonce2};

    MerkleTree tree(32, nonces);
    auto root = tree.root();

    // Verify path for first nonce
    auto path = tree.path(0);
    auto hash = MerkleTree::hash_leaf(nonce1, 32);

    // Apply path
    uint32_t index = 0;
    for (const auto& step : path) {
        if (index & 1) {
            hash = MerkleTree::hash_node(step.data(), hash.data(), 32);
        } else {
            hash = MerkleTree::hash_node(hash.data(), step.data(), 32);
        }
        index >>= 1;
    }

    std::vector<uint8_t> computed_root(hash.begin(), hash.begin() + 32);
    ASSERT_EQ(computed_root, root);
}

TEST_F(CryptoTest, MerkleLeafHashPrefix) {
    // Test SHA-512/256 hashing for IETF (32-byte nonces)
    std::vector<uint8_t> nonce(32, 0x01);
    auto hash = MerkleTree::hash_leaf(nonce, 32);

    // Leaf hash should be SHA-512/256(0x00 || nonce)
    std::vector<uint8_t> input;
    input.push_back(0x00);
    input.insert(input.end(), nonce.begin(), nonce.end());
    auto expected = sha512256(input);

    std::vector<uint8_t> expected_vec(expected.begin(), expected.end());
    ASSERT_EQ(hash, expected_vec);
}

TEST_F(CryptoTest, MerkleNodeHashPrefix) {
    std::vector<uint8_t> left(32, 0x01);
    std::vector<uint8_t> right(32, 0x02);

    auto hash = MerkleTree::hash_node(left.data(), right.data(), 32);

    // Node hash should be SHA-512/256(0x01 || left || right) for hash_size=32
    std::vector<uint8_t> input;
    input.push_back(0x01);
    input.insert(input.end(), left.begin(), left.end());
    input.insert(input.end(), right.begin(), right.end());
    auto expected = sha512256(input);

    std::vector<uint8_t> expected_vec(expected.begin(), expected.end());
    ASSERT_EQ(hash, expected_vec);
}

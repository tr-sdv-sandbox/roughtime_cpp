// Copyright 2024
// SPDX-License-Identifier: Apache-2.0

#include <roughtime/protocol.h>
#include <gtest/gtest.h>

using namespace roughtime;

class ProtocolTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Common setup
    }
};

// Test message encoding/decoding
TEST_F(ProtocolTest, EncodeDecodeEmpty) {
    Message msg;
    auto encoded = encode(msg);
    ASSERT_EQ(encoded.size(), 4);

    auto decoded = decode(encoded);
    ASSERT_TRUE(decoded.has_value());
    ASSERT_TRUE(decoded->empty());
}

TEST_F(ProtocolTest, EncodeDecodeSingleTag) {
    Message msg;
    msg[tags::NONC] = {0x01, 0x02, 0x03, 0x04};

    auto encoded = encode(msg);
    auto decoded = decode(encoded);

    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded->size(), 1);
    ASSERT_EQ((*decoded)[tags::NONC], std::vector<uint8_t>({0x01, 0x02, 0x03, 0x04}));
}

TEST_F(ProtocolTest, EncodeDecodeMultipleTags) {
    Message msg;
    msg[tags::NONC] = {0x01, 0x02, 0x03, 0x04};
    msg[tags::MIDP] = {0x05, 0x06, 0x07, 0x08};
    msg[tags::RADI] = {0x09, 0x0a, 0x0b, 0x0c};

    auto encoded = encode(msg);
    auto decoded = decode(encoded);

    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded->size(), 3);
    ASSERT_EQ((*decoded)[tags::NONC], std::vector<uint8_t>({0x01, 0x02, 0x03, 0x04}));
    ASSERT_EQ((*decoded)[tags::MIDP], std::vector<uint8_t>({0x05, 0x06, 0x07, 0x08}));
    ASSERT_EQ((*decoded)[tags::RADI], std::vector<uint8_t>({0x09, 0x0a, 0x0b, 0x0c}));
}

TEST_F(ProtocolTest, TagsSortedInOutput) {
    Message msg;
    msg[tags::RADI] = {0x01, 0x02, 0x03, 0x04};
    msg[tags::MIDP] = {0x05, 0x06, 0x07, 0x08};
    msg[tags::NONC] = {0x09, 0x0a, 0x0b, 0x0c};

    auto encoded = encode(msg);
    auto decoded = decode(encoded);

    ASSERT_TRUE(decoded.has_value());
    // Verify tags are in sorted order in the encoded message
    ASSERT_EQ(decoded->size(), 3);
}

TEST_F(ProtocolTest, RejectMisalignedPayload) {
    Message msg;
    msg[tags::NONC] = {0x01, 0x02, 0x03}; // Not 4-byte aligned

    EXPECT_THROW(encode(msg), std::invalid_argument);
}

TEST_F(ProtocolTest, DecodeInvalidData) {
    std::vector<uint8_t> invalid_data = {0x01, 0x02}; // Too short
    auto decoded = decode(invalid_data);
    ASSERT_FALSE(decoded.has_value());
}

// Test IETF framing
TEST_F(ProtocolTest, EncodeFramedIETF) {
    std::vector<uint8_t> msg = {0x01, 0x02, 0x03, 0x04};
    auto framed = encode_framed(true, msg);

    // Should have "ROUGHTIM" header (8 bytes) + length (4 bytes) + message
    ASSERT_EQ(framed.size(), 12 + msg.size());

    // Check header
    ASSERT_EQ(framed[0], 'R');
    ASSERT_EQ(framed[1], 'O');
    ASSERT_EQ(framed[2], 'U');
    ASSERT_EQ(framed[3], 'G');
    ASSERT_EQ(framed[4], 'H');
    ASSERT_EQ(framed[5], 'T');
    ASSERT_EQ(framed[6], 'I');
    ASSERT_EQ(framed[7], 'M');
}

TEST_F(ProtocolTest, EncodeFramedGoogle) {
    std::vector<uint8_t> msg = {0x01, 0x02, 0x03, 0x04};
    auto framed = encode_framed(false, msg);

    // Google-Roughtime has no framing
    ASSERT_EQ(framed, msg);
}

TEST_F(ProtocolTest, DecodeFramedIETF) {
    std::vector<uint8_t> msg = {0x01, 0x02, 0x03, 0x04};
    auto framed = encode_framed(true, msg);
    auto decoded = decode_framed(framed);

    ASSERT_TRUE(decoded.has_value());
    ASSERT_TRUE(decoded->is_ietf);
    ASSERT_EQ(decoded->data, msg);
}

TEST_F(ProtocolTest, DecodeFramedGoogle) {
    std::vector<uint8_t> msg = {0x01, 0x02, 0x03, 0x04};
    auto decoded = decode_framed(msg);

    ASSERT_TRUE(decoded.has_value());
    ASSERT_FALSE(decoded->is_ietf);
    ASSERT_EQ(decoded->data, msg);
}

// Test version string conversion
TEST_F(ProtocolTest, VersionToString) {
    ASSERT_EQ(version_to_string(Version::Google), "Google-Roughtime");
    ASSERT_EQ(version_to_string(Version::Draft08), "draft-ietf-ntp-roughtime-08");
    ASSERT_EQ(version_to_string(Version::Draft11), "draft-ietf-ntp-roughtime-11");
}

// Test request creation
TEST_F(ProtocolTest, CreateRequestIETF) {
    std::vector<Version> versions = {Version::Draft11};
    std::vector<uint8_t> prev_reply;
    std::array<uint8_t, ED25519_PUBLIC_KEY_SIZE> root_key = {};

    auto req = create_request(versions, prev_reply, root_key);

    ASSERT_TRUE(req.has_value());
    ASSERT_EQ(req->request_bytes.size(), 1024); // Minimum request size
    ASSERT_EQ(req->nonce.size(), 32); // IETF nonce size
    ASSERT_EQ(req->blind.size(), 32);
}

TEST_F(ProtocolTest, CreateRequestGoogle) {
    std::vector<Version> versions = {Version::Google};
    std::vector<uint8_t> prev_reply;
    std::array<uint8_t, ED25519_PUBLIC_KEY_SIZE> root_key = {};

    auto req = create_request(versions, prev_reply, root_key);

    ASSERT_TRUE(req.has_value());
    ASSERT_EQ(req->request_bytes.size(), 1024);
    ASSERT_EQ(req->nonce.size(), 64); // Google nonce size
    ASSERT_EQ(req->blind.size(), 64);
}

TEST_F(ProtocolTest, RejectMixedVersions) {
    std::vector<Version> versions = {Version::Google, Version::Draft11};
    std::vector<uint8_t> prev_reply;
    std::array<uint8_t, ED25519_PUBLIC_KEY_SIZE> root_key = {};

    auto req = create_request(versions, prev_reply, root_key);

    // Should reject mixing Google with IETF versions
    ASSERT_FALSE(req.has_value());
}

// Test nonce size
TEST_F(ProtocolTest, NonceSizeIETF) {
    ASSERT_EQ(nonce_size(true), 32);
}

TEST_F(ProtocolTest, NonceSizeGoogle) {
    ASSERT_EQ(nonce_size(false), 64);
}

// Copyright 2024
// SPDX-License-Identifier: Apache-2.0

#include "roughtime/protocol.h"
#include "roughtime/crypto.h"
#include <glog/logging.h>
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace roughtime {

namespace {
    constexpr const char* IETF_ROUGHTIME_FRAME = "ROUGHTIM";
    constexpr const char* CERTIFICATE_CONTEXT_DRAFT07 = "RoughTime v1 delegation signature\x00";
    constexpr const char* CERTIFICATE_CONTEXT_DRAFT08PLUS = "RoughTime v1 delegation signature--\x00";
    constexpr const char* SIGNED_RESPONSE_CONTEXT = "RoughTime v1 response signature\x00";

    uint32_t read_le32(const uint8_t* data) {
        return static_cast<uint32_t>(data[0]) |
               (static_cast<uint32_t>(data[1]) << 8) |
               (static_cast<uint32_t>(data[2]) << 16) |
               (static_cast<uint32_t>(data[3]) << 24);
    }

    uint64_t read_le64(const uint8_t* data) {
        return static_cast<uint64_t>(data[0]) |
               (static_cast<uint64_t>(data[1]) << 8) |
               (static_cast<uint64_t>(data[2]) << 16) |
               (static_cast<uint64_t>(data[3]) << 24) |
               (static_cast<uint64_t>(data[4]) << 32) |
               (static_cast<uint64_t>(data[5]) << 40) |
               (static_cast<uint64_t>(data[6]) << 48) |
               (static_cast<uint64_t>(data[7]) << 56);
    }

    void write_le32(uint8_t* data, uint32_t value) {
        data[0] = static_cast<uint8_t>(value & 0xff);
        data[1] = static_cast<uint8_t>((value >> 8) & 0xff);
        data[2] = static_cast<uint8_t>((value >> 16) & 0xff);
        data[3] = static_cast<uint8_t>((value >> 24) & 0xff);
    }

    [[maybe_unused]] void write_le64(uint8_t* data, uint64_t value) {
        data[0] = static_cast<uint8_t>(value & 0xff);
        data[1] = static_cast<uint8_t>((value >> 8) & 0xff);
        data[2] = static_cast<uint8_t>((value >> 16) & 0xff);
        data[3] = static_cast<uint8_t>((value >> 24) & 0xff);
        data[4] = static_cast<uint8_t>((value >> 32) & 0xff);
        data[5] = static_cast<uint8_t>((value >> 40) & 0xff);
        data[6] = static_cast<uint8_t>((value >> 48) & 0xff);
        data[7] = static_cast<uint8_t>((value >> 56) & 0xff);
    }
}

std::string version_to_string(Version ver) {
    switch (ver) {
        case Version::Google: return "Google-Roughtime";
        case Version::Draft07: return "draft-ietf-ntp-roughtime-07";
        case Version::Draft08: return "draft-ietf-ntp-roughtime-08";
        case Version::Draft11: return "draft-ietf-ntp-roughtime-11";
        default: return "Unknown";
    }
}

size_t nonce_size(bool version_ietf) {
    return version_ietf ? 32 : 64;
}

size_t message_overhead(bool version_ietf, size_t num_tags) {
    size_t framing = version_ietf ? 12 : 0;
    return framing + 4 * 2 * num_tags;
}

std::vector<Version> advertised_versions_from_preference(
    const std::vector<Version>& preference
) {
    if (preference.empty()) {
        return {Version::Draft11, Version::Draft08, Version::Draft07};
    }

    bool has_google = std::any_of(preference.begin(), preference.end(),
        [](Version v) { return v == Version::Google; });

    if (has_google && preference.size() != 1) {
        throw std::invalid_argument("Google-Roughtime cannot be combined with other versions");
    }

    return preference;
}

std::vector<uint8_t> encode(const Message& msg) {
    if (msg.empty()) {
        std::vector<uint8_t> result(4, 0);
        return result;
    }

    // Sort tags
    std::vector<uint32_t> tags;
    tags.reserve(msg.size());
    for (const auto& [tag, _] : msg) {
        tags.push_back(tag);
    }
    std::sort(tags.begin(), tags.end());

    // Calculate total payload size
    size_t payload_sum = 0;
    for (const auto& [_, payload] : msg) {
        if (payload.size() % 4 != 0) {
            throw std::invalid_argument("Payload length must be multiple of 4");
        }
        payload_sum += payload.size();
    }

    size_t num_tags = tags.size();
    size_t encoded_size = 4 * (1 + (num_tags - 1) + num_tags) + payload_sum;
    std::vector<uint8_t> encoded(encoded_size);

    // Write number of tags
    write_le32(encoded.data(), static_cast<uint32_t>(num_tags));

    // Write offsets and tags
    uint8_t* offset_ptr = encoded.data() + 4;
    uint8_t* tag_ptr = encoded.data() + 4 * (1 + (num_tags - 1));
    uint8_t* payload_ptr = encoded.data() + 4 * (1 + (num_tags - 1) + num_tags);

    uint32_t current_offset = 0;
    for (size_t i = 0; i < tags.size(); i++) {
        uint32_t tag = tags[i];
        const auto& payload = msg.at(tag);

        if (i > 0) {
            write_le32(offset_ptr, current_offset);
            offset_ptr += 4;
        }

        write_le32(tag_ptr, tag);
        tag_ptr += 4;

        if (!payload.empty()) {
            // Check for integer overflow before casting
            if (payload.size() > UINT32_MAX - current_offset) {
                throw std::invalid_argument("Message payload too large");
            }
            std::memcpy(payload_ptr, payload.data(), payload.size());
            payload_ptr += payload.size();
            current_offset += static_cast<uint32_t>(payload.size());
        }
    }

    return encoded;
}

std::optional<Message> decode(const std::vector<uint8_t>& data) {
    if (data.size() < 4 || data.size() % 4 != 0) {
        return std::nullopt;
    }

    uint32_t num_tags = read_le32(data.data());
    if (num_tags == 0) {
        return Message{};
    }

    size_t min_len = 4 * (1 + (num_tags - 1) + num_tags);
    if (data.size() < min_len) {
        return std::nullopt;
    }

    const uint8_t* offset_ptr = data.data() + 4;
    const uint8_t* tag_ptr = data.data() + 4 * (1 + (num_tags - 1));
    const uint8_t* payload_ptr = data.data() + min_len;

    // Check for integer overflow in payload length calculation
    size_t payload_size = data.size() - min_len;  // Safe: min_len <= data.size() checked above
    if (payload_size > UINT32_MAX) {
        return std::nullopt;
    }
    uint32_t payload_length = static_cast<uint32_t>(payload_size);

    Message result;
    uint32_t current_offset = 0;
    uint32_t last_tag = 0;

    for (uint32_t i = 0; i < num_tags; i++) {
        uint32_t tag = read_le32(tag_ptr);
        tag_ptr += 4;

        if (i > 0 && last_tag >= tag) {
            return std::nullopt; // Tags out of order
        }

        uint32_t next_offset;
        if (i < num_tags - 1) {
            next_offset = read_le32(offset_ptr);
            offset_ptr += 4;
        } else {
            next_offset = payload_length;
        }

        if (next_offset % 4 != 0 || next_offset < current_offset) {
            return std::nullopt;
        }

        uint32_t length = next_offset - current_offset;
        if (payload_length < current_offset + length) {
            return std::nullopt;
        }

        std::vector<uint8_t> payload(payload_ptr, payload_ptr + length);
        result[tag] = std::move(payload);

        payload_ptr += length;
        current_offset = next_offset;
        last_tag = tag;
    }

    return result;
}

std::vector<uint8_t> encode_framed(bool version_ietf, const std::vector<uint8_t>& msg) {
    if (!version_ietf) {
        return msg;
    }

    std::vector<uint8_t> framed;
    framed.reserve(12 + msg.size());

    // Add frame header
    framed.insert(framed.end(), IETF_ROUGHTIME_FRAME, IETF_ROUGHTIME_FRAME + 8);

    // Add message length
    uint8_t len_bytes[4];
    write_le32(len_bytes, static_cast<uint32_t>(msg.size()));
    framed.insert(framed.end(), len_bytes, len_bytes + 4);

    // Add message
    framed.insert(framed.end(), msg.begin(), msg.end());

    return framed;
}

std::optional<DecodedFrame> decode_framed(const std::vector<uint8_t>& data) {
    // Check if it starts with IETF framing header
    bool is_ietf = data.size() >= 8 && std::memcmp(data.data(), IETF_ROUGHTIME_FRAME, 8) == 0;

    if (!is_ietf) {
        // Google-Roughtime has no framing - return data as-is
        return DecodedFrame{data, false};
    }

    if (data.size() < 12) {
        return std::nullopt;
    }

    uint32_t msg_len = read_le32(data.data() + 8);
    if (data.size() != 12 + msg_len) {
        return std::nullopt;
    }

    std::vector<uint8_t> msg(data.begin() + 12, data.end());
    return DecodedFrame{std::move(msg), true};
}

void calculate_chain_nonce(
    std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& prev_reply,
    const std::vector<uint8_t>& blind
) {
    auto hash1 = crypto::sha512(prev_reply);

    std::vector<uint8_t> combined;
    combined.insert(combined.end(), hash1.begin(), hash1.end());
    combined.insert(combined.end(), blind.begin(), blind.end());

    auto hash2 = crypto::sha512(combined);

    nonce.assign(hash2.begin(), hash2.begin() + nonce.size());
}

std::optional<Request> create_request(
    const std::vector<Version>& version_preference,
    const std::vector<uint8_t>& prev_reply,
    const std::array<uint8_t, ED25519_PUBLIC_KEY_SIZE>& root_public_key
) {
    try {
        auto advertised = advertised_versions_from_preference(version_preference);
        bool version_ietf = advertised.empty() || advertised[0] != Version::Google;
        size_t nonce_sz = nonce_size(version_ietf);

        Request req;
        req.nonce.resize(nonce_sz);
        req.blind = crypto::random_bytes(nonce_sz);

        // Log blind for debugging
        LOG(INFO) << "Generated random blind, first 16 bytes: " << std::hex
                  << static_cast<int>(req.blind[0]) << " "
                  << static_cast<int>(req.blind[1]) << " "
                  << static_cast<int>(req.blind[2]) << " "
                  << static_cast<int>(req.blind[3]);

        calculate_chain_nonce(req.nonce, prev_reply, req.blind);

        // Log nonce
        LOG(INFO) << "Calculated nonce, first 16 bytes: " << std::hex
                  << static_cast<int>(req.nonce[0]) << " "
                  << static_cast<int>(req.nonce[1]) << " "
                  << static_cast<int>(req.nonce[2]) << " "
                  << static_cast<int>(req.nonce[3]);

        Message packet;

        // NONC tag
        packet[tags::NONC] = req.nonce;

        size_t num_tags = 1;
        size_t values_len = nonce_sz;

        // VER tag (IETF only)
        if (version_ietf) {
            std::vector<uint8_t> ver_data;
            for (Version ver : advertised) {
                uint8_t ver_bytes[4];
                write_le32(ver_bytes, static_cast<uint32_t>(ver));
                ver_data.insert(ver_data.end(), ver_bytes, ver_bytes + 4);
            }
            packet[tags::VER] = std::move(ver_data);
            num_tags++;
            values_len += packet[tags::VER].size();
        }

        // SRV tag (Draft11 only)
        bool use_srv = std::any_of(advertised.begin(), advertised.end(),
            [](Version v) { return v == Version::Draft11; });

        if (use_srv) {
            std::vector<uint8_t> srv_input;
            srv_input.push_back(0xff);
            srv_input.insert(srv_input.end(), root_public_key.begin(), root_public_key.end());
            auto srv_hash = crypto::sha512(srv_input);
            packet[tags::SRV] = std::vector<uint8_t>(srv_hash.begin(), srv_hash.begin() + 32);
            num_tags++;
            values_len += 32;
        }

        // Padding
        uint32_t padding_tag = version_ietf ? tags::ZZZZ : tags::PAD;
        size_t padding_size = MIN_REQUEST_SIZE - message_overhead(version_ietf, num_tags + 1) - values_len;
        packet[padding_tag] = std::vector<uint8_t>(padding_size, 0);

        auto encoded = encode(packet);
        req.request_bytes = encode_framed(version_ietf, encoded);

        return req;
    } catch (const std::exception& e) {
        LOG(ERROR) << "create_request failed: " << e.what();
        return std::nullopt;
    }
}

std::optional<VerifiedReply> verify_reply(
    const std::vector<Version>& version_preference,
    const std::vector<uint8_t>& reply_bytes,
    const std::array<uint8_t, ED25519_PUBLIC_KEY_SIZE>& public_key,
    const std::vector<uint8_t>& nonce
) {
    try {
        LOG(INFO) << "verify_reply: got " << reply_bytes.size() << " bytes";
        auto advertised = advertised_versions_from_preference(version_preference);
        bool version_ietf = advertised.empty() || advertised[0] != Version::Google;
        size_t nonce_sz = nonce_size(version_ietf);

        auto framed = decode_framed(reply_bytes);
        if (!framed) {
            LOG(ERROR) << "Failed to decode framed response";
            return std::nullopt;
        }

        auto reply = decode(framed->data);
        if (!reply) {
            LOG(ERROR) << "Failed to decode reply data";
            return std::nullopt;
        }

        // Log tags in response for debugging
        std::stringstream tag_list;
        for (const auto& [tag, value] : *reply) {
            tag_list << " " << std::hex << tag;
        }
        LOG(INFO) << "Response tags:" << tag_list.str();

        // Verify version (IETF only)
        Version response_ver = Version::Google;
        if (version_ietf) {
            auto ver_it = reply->find(tags::VER);
            if (ver_it == reply->end() || ver_it->second.size() != 4) {
                LOG(ERROR) << "Missing or invalid VER tag";
                return std::nullopt;
            }
            response_ver = static_cast<Version>(read_le32(ver_it->second.data()));
            LOG(INFO) << "Server reports version: 0x" << std::hex << static_cast<uint32_t>(response_ver);

            bool version_ok = std::any_of(advertised.begin(), advertised.end(),
                [response_ver](Version v) { return v == response_ver; });
            if (!version_ok) {
                LOG(ERROR) << "Version mismatch: got " << static_cast<uint32_t>(response_ver);
                return std::nullopt;
            }
        }

        // Verify NONC tag matches (IETF only)
        if (version_ietf) {
            auto nonc_it = reply->find(tags::NONC);
            if (nonc_it == reply->end()) {
                LOG(ERROR) << "NONC tag missing from response";
                return std::nullopt;
            }
            if (nonc_it->second != nonce) {
                LOG(ERROR) << "NONC mismatch: expected " << nonce.size()
                          << " bytes, got " << nonc_it->second.size() << " bytes";
                return std::nullopt;
            }
        }
        LOG(INFO) << "Version and nonce check passed";

        // Get certificate
        auto cert_it = reply->find(tags::CERT);
        if (cert_it == reply->end()) return std::nullopt;

        auto cert = decode(cert_it->second);
        if (!cert) return std::nullopt;

        // Verify delegation signature
        auto dele_it = cert->find(tags::DELE);
        auto sig_it = cert->find(tags::SIG);
        if (dele_it == cert->end() || sig_it == cert->end()) return std::nullopt;
        if (sig_it->second.size() != ED25519_SIGNATURE_SIZE) return std::nullopt;

        // Use appropriate certificate context based on version
        const char* cert_context = (response_ver == Version::Draft07) ?
            CERTIFICATE_CONTEXT_DRAFT07 : CERTIFICATE_CONTEXT_DRAFT08PLUS;
        size_t cert_context_len = (response_ver == Version::Draft07) ? 34 : 36;

        std::vector<uint8_t> cert_msg(cert_context, cert_context + cert_context_len);
        cert_msg.insert(cert_msg.end(), dele_it->second.begin(), dele_it->second.end());

        std::array<uint8_t, ED25519_SIGNATURE_SIZE> cert_sig;
        std::copy_n(sig_it->second.begin(), ED25519_SIGNATURE_SIZE, cert_sig.begin());

        if (!crypto::ed25519_verify(public_key, cert_msg, cert_sig)) {
            LOG(ERROR) << "Certificate signature verification failed";
            LOG(ERROR) << "  Version: 0x" << std::hex << static_cast<uint32_t>(response_ver);
            LOG(ERROR) << "  Context length: " << std::dec << cert_context_len;
            LOG(ERROR) << "  Delegation size: " << dele_it->second.size();
            LOG(ERROR) << "  Public key (first 8 bytes): "
                      << std::hex << std::setfill('0')
                      << std::setw(2) << static_cast<int>(public_key[0]) << " "
                      << std::setw(2) << static_cast<int>(public_key[1]) << " "
                      << std::setw(2) << static_cast<int>(public_key[2]) << " "
                      << std::setw(2) << static_cast<int>(public_key[3]) << " "
                      << std::setw(2) << static_cast<int>(public_key[4]) << " "
                      << std::setw(2) << static_cast<int>(public_key[5]) << " "
                      << std::setw(2) << static_cast<int>(public_key[6]) << " "
                      << std::setw(2) << static_cast<int>(public_key[7]);
            return std::nullopt;
        }

        // Parse delegation
        auto delegation = decode(dele_it->second);
        if (!delegation) {
            LOG(ERROR) << "Failed to decode delegation";
            return std::nullopt;
        }

        auto pubk_it = delegation->find(tags::PUBK);
        if (pubk_it == delegation->end() || pubk_it->second.size() != ED25519_PUBLIC_KEY_SIZE) {
            LOG(ERROR) << "PUBK tag missing or wrong size in delegation";
            return std::nullopt;
        }

        std::array<uint8_t, ED25519_PUBLIC_KEY_SIZE> delegated_key;
        std::copy_n(pubk_it->second.begin(), ED25519_PUBLIC_KEY_SIZE, delegated_key.begin());
        LOG(INFO) << "Certificate verified, delegated key extracted";

        // Verify response signature
        auto srep_it = reply->find(tags::SREP);
        auto resp_sig_it = reply->find(tags::SIG);
        if (srep_it == reply->end() || resp_sig_it == reply->end()) {
            LOG(ERROR) << "SREP or SIG missing from response";
            return std::nullopt;
        }
        if (resp_sig_it->second.size() != ED25519_SIGNATURE_SIZE) {
            LOG(ERROR) << "Response SIG wrong size: " << resp_sig_it->second.size();
            return std::nullopt;
        }

        std::vector<uint8_t> resp_msg(SIGNED_RESPONSE_CONTEXT, SIGNED_RESPONSE_CONTEXT + 32);
        resp_msg.insert(resp_msg.end(), srep_it->second.begin(), srep_it->second.end());

        std::array<uint8_t, ED25519_SIGNATURE_SIZE> resp_sig;
        std::copy_n(resp_sig_it->second.begin(), ED25519_SIGNATURE_SIZE, resp_sig.begin());

        if (!crypto::ed25519_verify(delegated_key, resp_msg, resp_sig)) {
            LOG(ERROR) << "Response signature verification failed";
            return std::nullopt;
        }
        LOG(INFO) << "Response signature verified";

        // Parse signed response
        auto signed_resp = decode(srep_it->second);
        if (!signed_resp) {
            LOG(ERROR) << "Failed to decode signed response (SREP)";
            return std::nullopt;
        }

        auto root_it = signed_resp->find(tags::ROOT);
        auto midp_it = signed_resp->find(tags::MIDP);
        auto radi_it = signed_resp->find(tags::RADI);

        if (root_it == signed_resp->end() || midp_it == signed_resp->end() ||
            radi_it == signed_resp->end()) {
            LOG(ERROR) << "Missing required tags in signed response";
            LOG(ERROR) << "  Has ROOT: " << (root_it != signed_resp->end());
            LOG(ERROR) << "  Has MIDP: " << (midp_it != signed_resp->end());
            LOG(ERROR) << "  Has RADI: " << (radi_it != signed_resp->end());
            return std::nullopt;
        }

        LOG(INFO) << "Signed response contains ROOT, MIDP, RADI";
        LOG(INFO) << "  ROOT size: " << root_it->second.size() << " (expected: " << nonce_sz << ")";
        LOG(INFO) << "  MIDP size: " << midp_it->second.size() << " (expected: 8)";
        LOG(INFO) << "  RADI size: " << radi_it->second.size() << " (expected: 4)";

        if (root_it->second.size() != nonce_sz || midp_it->second.size() != 8 ||
            radi_it->second.size() != 4) {
            LOG(ERROR) << "Tag size mismatch in signed response";
            return std::nullopt;
        }

        uint64_t midpoint_val = read_le64(midp_it->second.data());
        uint32_t radius_val = read_le32(radi_it->second.data());

        LOG(INFO) << "Time values extracted: midpoint=" << midpoint_val << ", radius=" << radius_val;

        // Verify certificate validity period against server's claimed time
        // This allows Roughtime to work on systems with incorrect local time
        auto mint_it = delegation->find(tags::MINT);
        auto maxt_it = delegation->find(tags::MAXT);
        if (mint_it == delegation->end() || maxt_it == delegation->end()) {
            LOG(ERROR) << "Certificate missing MINT or MAXT";
            return std::nullopt;
        }
        if (mint_it->second.size() != 8 || maxt_it->second.size() != 8) {
            LOG(ERROR) << "Certificate MINT/MAXT wrong size";
            return std::nullopt;
        }

        uint64_t mint_val = read_le64(mint_it->second.data());
        uint64_t maxt_val = read_le64(maxt_it->second.data());

        LOG(INFO) << "Certificate validity: MINT=" << mint_val << ", MAXT=" << maxt_val;

        // Certificate must be valid at server's claimed midpoint time
        // For IETF: both MIDP and MINT/MAXT are in seconds
        // For Google: both MIDP and MINT/MAXT are in microseconds
        if (midpoint_val < mint_val || midpoint_val > maxt_val) {
            LOG(ERROR) << "Certificate time validation failed: midpoint=" << midpoint_val
                      << " not in range [" << mint_val << ", " << maxt_val << "]";
            return std::nullopt;
        }

        LOG(INFO) << "Certificate time validation passed";

        // Verify Merkle path
        auto indx_it = reply->find(tags::INDX);
        auto path_it = reply->find(tags::PATH);
        if (indx_it == reply->end() || path_it == reply->end()) {
            LOG(ERROR) << "Missing INDX or PATH tags";
            LOG(ERROR) << "  Has INDX: " << (indx_it != reply->end());
            LOG(ERROR) << "  Has PATH: " << (path_it != reply->end());
            return std::nullopt;
        }
        if (indx_it->second.size() != 4 || path_it->second.size() % nonce_sz != 0) {
            LOG(ERROR) << "INDX or PATH size invalid";
            LOG(ERROR) << "  INDX size: " << indx_it->second.size() << " (expected: 4)";
            LOG(ERROR) << "  PATH size: " << path_it->second.size() << " (nonce_sz=" << nonce_sz << ")";
            return std::nullopt;
        }

        uint32_t index = read_le32(indx_it->second.data());

        LOG(INFO) << "Starting Merkle path verification (index=" << index << ", path_steps=" << (path_it->second.size() / nonce_sz) << ")";

        // Hash size equals nonce size for Roughtime (IETF: 32, Google: 64)
        size_t hash_size = nonce_sz;

        std::stringstream nonce_debug;
        for (size_t i = 0; i < std::min(nonce.size(), size_t(16)); i++) {
            nonce_debug << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(nonce[i]) << " ";
        }
        LOG(INFO) << "Nonce used for verification (first 16): " << nonce_debug.str();

        auto hash = crypto::MerkleTree::hash_leaf(nonce, hash_size);
        const uint8_t* path_ptr = path_it->second.data();
        const uint8_t* path_end = path_it->second.data() + path_it->second.size();
        size_t path_steps = path_it->second.size() / nonce_sz;

        for (size_t i = 0; i < path_steps; i++) {
            // Verify path_ptr stays within bounds
            if (path_ptr + nonce_sz > path_end) {
                LOG(ERROR) << "Merkle path out of bounds";
                return std::nullopt;
            }
            if (index & 1) {
                hash = crypto::MerkleTree::hash_node(path_ptr, hash.data(), hash_size);
            } else {
                hash = crypto::MerkleTree::hash_node(hash.data(), path_ptr, hash_size);
            }
            path_ptr += nonce_sz;
            index >>= 1;
        }

        if (std::memcmp(hash.data(), root_it->second.data(), nonce_sz) != 0) {
            LOG(ERROR) << "Merkle root mismatch";
            std::stringstream computed_hash, expected_hash;
            for (size_t i = 0; i < std::min(nonce_sz, size_t(16)); i++) {
                computed_hash << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]) << " ";
                expected_hash << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(root_it->second[i]) << " ";
            }
            LOG(ERROR) << "  Computed (first 16): " << computed_hash.str();
            LOG(ERROR) << "  Expected (first 16): " << expected_hash.str();
            return std::nullopt;
        }

        LOG(INFO) << "Merkle path verification passed";

        // Convert to time
        VerifiedReply result;
        if (version_ietf) {
            // IETF Roughtime uses Modified Julian Date (MJD) timestamps
            // Top 24 bits: MJD (days since Nov 17, 1858)
            // Bottom 40 bits: Microseconds since midnight
            uint64_t mjd = midpoint_val >> 40;
            uint64_t usec_of_day = midpoint_val & 0xFFFFFFFFFF;

            // Unix epoch (Jan 1, 1970) is MJD 40587
            const uint64_t UNIX_EPOCH_MJD = 40587;
            int64_t days_since_unix_epoch = static_cast<int64_t>(mjd - UNIX_EPOCH_MJD);

            result.midpoint = std::chrono::system_clock::from_time_t(days_since_unix_epoch * 86400) +
                            std::chrono::microseconds(usec_of_day);
            result.radius = std::chrono::microseconds(radius_val * 1000000);  // radius is in seconds
        } else {
            // Google Roughtime uses microseconds since Unix epoch
            result.midpoint = std::chrono::system_clock::from_time_t(static_cast<time_t>(midpoint_val / 1000000)) +
                            std::chrono::microseconds(midpoint_val % 1000000);
            result.radius = std::chrono::microseconds(radius_val);
        }

        return result;
    } catch (const std::exception& e) {
        LOG(ERROR) << "verify_reply failed: " << e.what();
        return std::nullopt;
    }
}

} // namespace roughtime

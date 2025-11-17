// Copyright 2024
// SPDX-License-Identifier: Apache-2.0
//
// RAII wrappers for OpenSSL resources
// Provides exception-safe automatic resource management

#pragma once

#include <openssl/evp.h>
#include <stdexcept>
#include <utility>

namespace roughtime {
namespace crypto {

/**
 * @brief RAII wrapper for EVP_MD_CTX
 *
 * Automatically manages the lifecycle of an OpenSSL message digest context.
 * Ensures the context is properly freed even if exceptions are thrown.
 */
class EVPMDContext {
public:
    EVPMDContext() : ctx_(EVP_MD_CTX_new()) {
        if (!ctx_) {
            throw std::runtime_error("Failed to create EVP_MD_CTX");
        }
    }

    ~EVPMDContext() {
        if (ctx_) {
            EVP_MD_CTX_free(ctx_);
        }
    }

    // Disable copying
    EVPMDContext(const EVPMDContext&) = delete;
    EVPMDContext& operator=(const EVPMDContext&) = delete;

    // Enable moving
    EVPMDContext(EVPMDContext&& other) noexcept : ctx_(other.ctx_) {
        other.ctx_ = nullptr;
    }

    EVPMDContext& operator=(EVPMDContext&& other) noexcept {
        if (this != &other) {
            if (ctx_) {
                EVP_MD_CTX_free(ctx_);
            }
            ctx_ = other.ctx_;
            other.ctx_ = nullptr;
        }
        return *this;
    }

    EVP_MD_CTX* get() const { return ctx_; }
    EVP_MD_CTX* operator->() const { return ctx_; }

private:
    EVP_MD_CTX* ctx_;
};

/**
 * @brief RAII wrapper for EVP_PKEY
 *
 * Automatically manages the lifecycle of an OpenSSL public/private key.
 * Ensures the key is properly freed even if exceptions are thrown.
 */
class EVPPKey {
public:
    explicit EVPPKey(EVP_PKEY* pkey = nullptr) : pkey_(pkey) {}

    ~EVPPKey() {
        if (pkey_) {
            EVP_PKEY_free(pkey_);
        }
    }

    // Disable copying
    EVPPKey(const EVPPKey&) = delete;
    EVPPKey& operator=(const EVPPKey&) = delete;

    // Enable moving
    EVPPKey(EVPPKey&& other) noexcept : pkey_(other.pkey_) {
        other.pkey_ = nullptr;
    }

    EVPPKey& operator=(EVPPKey&& other) noexcept {
        if (this != &other) {
            if (pkey_) {
                EVP_PKEY_free(pkey_);
            }
            pkey_ = other.pkey_;
            other.pkey_ = nullptr;
        }
        return *this;
    }

    EVP_PKEY* get() const { return pkey_; }
    EVP_PKEY* operator->() const { return pkey_; }

    /**
     * @brief Release ownership of the EVP_PKEY
     * @return The underlying EVP_PKEY pointer
     * @note Caller is responsible for freeing the returned pointer
     */
    EVP_PKEY* release() {
        EVP_PKEY* p = pkey_;
        pkey_ = nullptr;
        return p;
    }

    /**
     * @brief Reset with a new EVP_PKEY
     * @param pkey New EVP_PKEY to manage (can be nullptr)
     */
    void reset(EVP_PKEY* pkey = nullptr) {
        if (pkey_) {
            EVP_PKEY_free(pkey_);
        }
        pkey_ = pkey;
    }

    explicit operator bool() const { return pkey_ != nullptr; }

private:
    EVP_PKEY* pkey_;
};

/**
 * @brief RAII wrapper for EVP_PKEY_CTX
 *
 * Automatically manages the lifecycle of an OpenSSL key context.
 * Ensures the context is properly freed even if exceptions are thrown.
 */
class EVPPKeyContext {
public:
    explicit EVPPKeyContext(EVP_PKEY_CTX* ctx = nullptr) : ctx_(ctx) {}

    ~EVPPKeyContext() {
        if (ctx_) {
            EVP_PKEY_CTX_free(ctx_);
        }
    }

    // Disable copying
    EVPPKeyContext(const EVPPKeyContext&) = delete;
    EVPPKeyContext& operator=(const EVPPKeyContext&) = delete;

    // Enable moving
    EVPPKeyContext(EVPPKeyContext&& other) noexcept : ctx_(other.ctx_) {
        other.ctx_ = nullptr;
    }

    EVPPKeyContext& operator=(EVPPKeyContext&& other) noexcept {
        if (this != &other) {
            if (ctx_) {
                EVP_PKEY_CTX_free(ctx_);
            }
            ctx_ = other.ctx_;
            other.ctx_ = nullptr;
        }
        return *this;
    }

    EVP_PKEY_CTX* get() const { return ctx_; }
    EVP_PKEY_CTX* operator->() const { return ctx_; }

    void reset(EVP_PKEY_CTX* ctx = nullptr) {
        if (ctx_) {
            EVP_PKEY_CTX_free(ctx_);
        }
        ctx_ = ctx;
    }

    explicit operator bool() const { return ctx_ != nullptr; }

private:
    EVP_PKEY_CTX* ctx_;
};

} // namespace crypto
} // namespace roughtime

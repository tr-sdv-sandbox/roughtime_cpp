# Roughtime C++ Architecture

This document describes the architecture and design of the Roughtime C++ implementation.

## Overview

This is a modern C++17 implementation of the Roughtime protocol, supporting both:
- **IETF Roughtime** (drafts 07, 08, 11)
- **Google Roughtime** (original specification)

The implementation consists of a client library, server library, and command-line tools.

## Directory Structure

```
roughtime_cpp/
├── include/roughtime/      # Public headers
│   ├── config.h           # Build configuration
│   ├── protocol.h         # Protocol implementation
│   ├── crypto.h           # Cryptographic primitives
│   ├── client.h           # Client API
│   ├── server.h           # Server API
│   ├── validation.h       # Input validation
│   ├── rate_limiter.h     # DoS protection
│   └── openssl_wrappers.h # RAII wrappers for OpenSSL
├── src/                   # Core implementation
│   ├── protocol.cpp       # Protocol encoding/decoding
│   ├── crypto.cpp         # Crypto operations (SHA-512, Ed25519, Merkle trees)
│   └── client.cpp         # Client implementation
├── server/                # Server implementation
│   ├── include/           # Server headers
│   ├── src/
│   │   ├── server.cpp     # Server core logic
│   │   └── main.cpp       # Server binary entry point
├── cli/                   # Command-line client
│   └── getroughtime.cpp   # CLI tool implementation
├── tests/                 # Test suite
│   ├── *_test.cpp         # Unit tests
│   └── test_utils.h       # Shared test utilities
├── deployment/            # Production deployment files
│   ├── roughtime-server.service  # Systemd service
│   └── README.md          # Deployment guide
└── docs/                  # Documentation
    └── ARCHITECTURE.md    # This file
```

## Core Components

### 1. Protocol Layer (`protocol.h/cpp`)

Handles Roughtime protocol encoding/decoding:

**Key Functions:**
- `encode(Message)` - Encode tags into wire format
- `decode(bytes)` - Decode wire format into tags
- `encode_framed()` / `decode_framed()` - IETF framing
- `create_request()` - Build client requests
- `verify_reply()` - Verify and parse server responses

**Protocol Versions:**
- Google-Roughtime: 64-byte nonces, microsecond timestamps
- IETF Draft 07/08/11: 32-byte nonces, MJD timestamps

### 2. Cryptography Layer (`crypto.h/cpp`)

Implements cryptographic primitives using OpenSSL:

**Hash Functions:**
- `sha512()` - SHA-512 hashing
- `sha512256()` - SHA-512/256 (IETF Roughtime)
- `sha512_multi()` - Multi-part hashing

**Digital Signatures:**
- `ed25519_verify()` - Ed25519 signature verification
- Ed25519 key generation (in server)

**Merkle Trees:**
- `MerkleTree` class for batch request handling
- Supports both 32-byte and 64-byte hash sizes
- Leaf/node hash prefixes (0x00 and 0x01)

### 3. Client Library (`client.h/cpp`)

Provides client API for querying Roughtime servers:

**Main Class:** `Client`
- `query()` - Query single server
- `get_trusted_time()` - Query multiple servers with consensus

**Features:**
- Automatic retry logic
- Chained queries (using previous response as blind)
- Median timestamp calculation
- Outlier detection for rogue servers
- UDP socket handling

### 4. Server Library (`server.h`, `server/src/server.cpp`)

Implements Roughtime server:

**Key Components:**
- `Server` class - Main server implementation
- `ServerConfig` - Configuration structure
- `Certificate` - Delegation certificate management
- `parse_request()` - Request parsing
- `create_replies()` - Batch response generation

**Features:**
- Dual-protocol support (IETF and Google)
- Certificate delegation (root → online key)
- Batch request processing via Merkle trees
- Configurable uncertainty radius
- Rate limiting (token bucket algorithm)
- Input validation

### 5. OpenSSL RAII Wrappers (`openssl_wrappers.h`)

Exception-safe resource management for OpenSSL:

**Classes:**
- `EVPMDContext` - Wraps `EVP_MD_CTX*`
- `EVPPKey` - Wraps `EVP_PKEY*`
- `EVPPKeyContext` - Wraps `EVP_PKEY_CTX*`

**Benefits:**
- Automatic cleanup (no memory leaks)
- Move semantics (efficient transfer)
- Exception safety
- Eliminated ~50+ manual `free()` calls

### 6. Security Features

#### Input Validation (`validation.h`)
- Request/response size limits
- Timestamp bounds checking
- Nonce size validation
- Batch size limits
- Server configuration validation

#### Rate Limiting (`rate_limiter.h`)
- Token bucket algorithm
- Per-IP rate limiting
- Configurable limits (default: 100 req/10sec)
- Automatic cleanup of stale entries
- Thread-safe implementation

## Protocol Flow

### Client Query Flow

```
1. Client generates random nonce (32 or 64 bytes)
2. Client creates REQUEST with NONC, VER tags
3. Client adds framing (for IETF) and pads to 1024 bytes
4. Client sends UDP packet to server
5. Client receives RESPONSE
6. Client verifies:
   - Certificate signature (root key → delegated key)
   - Certificate time validity
   - Response signature (delegated key)
   - Merkle tree proof (nonce → root)
7. Client extracts midpoint and radius
```

### Server Response Flow

```
1. Server receives REQUEST packet
2. Server validates request size
3. Server checks rate limit for client IP
4. Server parses REQUEST (nonce, versions)
5. Server selects protocol version
6. Server builds Merkle tree from batch nonces
7. Server creates SREP with:
   - ROOT (Merkle root)
   - MIDP (current time)
   - RADI (uncertainty radius)
8. Server signs SREP with delegated key
9. Server creates RESPONSE with:
   - CERT (delegation certificate)
   - SREP (signed response)
   - INDX (Merkle tree index)
   - PATH (Merkle tree path)
10. Server adds framing and sends UDP response
```

## Key Design Decisions

### 1. Dual Protocol Support

The implementation supports both IETF and Google Roughtime to maximize compatibility:
- Automatic protocol detection from requests
- Separate certificate formats
- Different timestamp encodings (MJD vs microseconds)

### 2. RAII for Resource Management

All OpenSSL resources use RAII wrappers:
- Prevents memory leaks
- Exception-safe
- Cleaner code (no manual cleanup)

### 3. Batch Request Processing

Server uses Merkle trees to efficiently handle multiple requests:
- Single timestamp for entire batch
- Individual proof for each client
- Prevents selective time manipulation

### 4. Certificate Delegation

Root key stays offline; online key rotates regularly:
- Root key signs delegation certificate
- Online key signs responses
- Limits exposure if online key compromised

### 5. Rate Limiting

Token bucket algorithm prevents DoS attacks:
- Per-IP tracking
- Configurable limits
- Fail-open for new IPs when table full
- Automatic cleanup

## Security Considerations

### Cryptography
- Ed25519 for signatures (128-bit security)
- SHA-512/256 for IETF (256-bit)
- SHA-512 for Google (512-bit)
- Merkle trees prevent timestamp manipulation

### Network Security
- UDP only (stateless, no connection overhead)
- Request padding (prevents traffic analysis)
- Rate limiting (DoS protection)
- Input validation (prevents malformed requests)

### Key Management
- Root key should be kept offline
- Online key rotates via certificates
- Certificate validity limited (default: 72 hours)

### Systemd Hardening
- Runs as unprivileged user
- Restricted filesystem access
- Limited system calls
- Private /tmp
- Resource limits

## Performance Characteristics

### Throughput
- Single-threaded: ~2,000 requests/sec
- Multi-threaded (10 threads): ~2,000 requests/sec
- Latency: <1ms average, <2ms p99

### Resource Usage
- Memory: ~5MB base + ~100 bytes per tracked IP
- CPU: Minimal (mostly crypto operations)
- Network: ~1KB per request/response pair

### Scalability
- Stateless (except rate limiting)
- Horizontal scaling via multiple servers
- No database required
- Low resource requirements

## Testing Strategy

### Unit Tests
- Protocol encoding/decoding
- Cryptographic operations
- Merkle tree construction

### Integration Tests
- Client-server interaction
- Multi-server consensus
- Protocol version negotiation

### Security Tests
- Rogue server detection
- Invalid signature rejection
- Merkle proof verification
- Certificate validation

### Performance Tests
- Single-threaded throughput
- Concurrent request handling
- Latency consistency
- Burst load handling

## Future Enhancements

Potential areas for improvement:
1. YAML configuration file support
2. Metrics/monitoring framework (Prometheus)
3. IPv6 support
4. Multiple root keys (key rotation)
5. Persistent statistics
6. Admin API (health checks, statistics)
7. Docker containerization
8. Kubernetes deployment manifests

## References

- [IETF Roughtime Draft 11](https://datatracker.ietf.org/doc/draft-ietf-ntp-roughtime/)
- [Google Roughtime Specification](https://roughtime.googlesource.com/roughtime/+/HEAD/PROTOCOL.md)
- [Cloudflare's Roughtime](https://blog.cloudflare.com/roughtime/)

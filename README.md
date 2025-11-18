# Roughtime C++

[![CI](https://github.com/tr-sdv-sandbox/roughtime_cpp/actions/workflows/ci.yml/badge.svg)](https://github.com/tr-sdv-sandbox/roughtime_cpp/actions/workflows/ci.yml)

A modern C++17 implementation of the Roughtime protocol, based on Cloudflare's Go implementation. This implementation includes both a high-performance server and full-featured client supporting Google-Roughtime and IETF-Roughtime protocols (draft-07, draft-08, draft-11, and draft-14).

## Features

### Client
- ✅ Full support for Google-Roughtime protocol
- ✅ Full support for IETF-Roughtime (draft-07, draft-08, draft-11, draft-14)
- ✅ Automatic protocol version negotiation (prefers draft-14)
- ✅ Ed25519 signature verification
- ✅ Merkle tree verification
- ✅ Request chaining
- ✅ UDP networking with timeout and retries
- ✅ JSON configuration file support
- ✅ Command-line interface similar to Cloudflare's `getroughtime`
- ✅ Trusted time API with multi-server consensus

### Server
- ✅ High-performance UDP server (10,000+ req/s)
- ✅ Automatic protocol version negotiation (supports draft-07/08/11/14)
- ✅ Support for both Google-Roughtime and IETF-Roughtime
- ✅ Certificate delegation with automatic rotation
- ✅ Sub-millisecond average latency
- ✅ Comprehensive test suite with 77 tests
- ✅ GitHub Actions CI with sanitizer checks (ASan, UBSan)

### Cryptography
- ✅ SHA-512/256 (FIPS 180-4) for IETF Roughtime
- ✅ SHA-512 for Google Roughtime
- ✅ Ed25519 signatures with OpenSSL
- ✅ Multiple timestamp formats:
  - Modified Julian Date (MJD) for draft-07/08/11
  - Unix seconds for draft-14
  - Unix microseconds for Google-Roughtime
- ✅ Modern C++17 code with proper error handling

## Requirements

- C++17 compatible compiler (GCC 7+, Clang 5+, MSVC 2017+)
- CMake 3.14 or later
- OpenSSL (for Ed25519 signatures and SHA-512/256)
- glog (for logging)
- GoogleTest (for testing)
- nlohmann-json (for JSON parsing)
- pkg-config

## Dependencies

All dependencies are installed via system package managers (no auto-downloading):

- **OpenSSL**: Cryptographic library for Ed25519 signatures, SHA-512, and SHA-512/256 (FIPS 180-4)
- **glog**: Google's logging library for structured logging
- **nlohmann/json**: Modern C++ JSON library
- **GoogleTest**: Testing framework

Use the provided `install.sh` script to install all dependencies automatically.

## Building

### Quick Start (Recommended)

```bash
# Install all dependencies automatically
./install.sh

# Build the project
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . -j$(nproc)

# Run tests
ctest --output-on-failure

# Install (optional)
sudo make install
```

The `install.sh` script automatically detects your OS and installs all required dependencies for:
- Ubuntu/Debian
- Fedora/RHEL/CentOS
- Arch Linux
- macOS (requires Homebrew)

### Manual Installation

#### Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential cmake pkg-config \
    libssl-dev libgoogle-glog-dev \
    libgtest-dev nlohmann-json3-dev
```

#### Fedora/RHEL

```bash
sudo dnf install -y \
    gcc-c++ cmake pkg-config \
    openssl-devel glog-devel \
    gtest-devel json-devel
```

#### macOS

```bash
brew install cmake pkg-config openssl glog googletest nlohmann-json
```

## Usage

### Client Usage

#### Query Servers from Configuration File

```bash
./build/getroughtime -c examples/servers.json
```

Example output:
```
txryan-1: 2025-11-17 05:57:33 UTC ±1s (in 254ms)
Netnod-sth1: 2025-11-17 05:57:33 UTC ±96s (in 197ms)
Netnod-sth2: 2025-11-17 05:57:33 UTC ±36s (in 200ms)

Trusted time: 2025-11-17 05:57:32 UTC ±96s (3/3 servers, TRUSTED)
```

#### Ping a Single Server

```bash
./build/getroughtime --ping roughtime.cloudflare.com:2002 \
    --pubkey gD63hSj3ScS+wuOeGrubXlq35N1c5Lby/S+T7MNTjxo= \
    --ping-version IETF-Roughtime
```

Example output:
```
Ping response: 2025-11-17 05:57:33 UTC ±1s (in 45ms)
```

### Server Usage

#### Run the Roughtime Server

```bash
./build/roughtime-server --addr 0.0.0.0 --port 2002
```

The server automatically:
- Generates an online keypair on startup
- Creates delegation certificates valid for 48 hours
- Supports both Google-Roughtime and IETF-Roughtime protocols
- Negotiates protocol versions with clients
- Uses MJD timestamps for IETF-Roughtime

#### Server Command-Line Options

```
Usage: roughtime-server [OPTIONS]

Options:
  --addr ADDRESS    Listen address (default: 127.0.0.1)
  --port PORT       Listen port (default: 2002)
  --help           Show this help message
```

**Note**: The server uses an ephemeral root key generated at startup. For production use, you should modify the server to load a persistent root key from a secure location.

### Command-Line Options

```
Usage: getroughtime [OPTIONS]

Options:
  -c, --config FILE      JSON configuration file with server list
  -p, --ping ADDR        Ping a single server (e.g., localhost:2002)
  -k, --pubkey KEY       Base64-encoded Ed25519 public key for ping
  -v, --ping-version VER Version for ping (default: IETF-Roughtime)
                         Options: IETF-Roughtime (prefers draft-14), Google-Roughtime
  -a, --attempts NUM     Number of query attempts per server (default: 3)
  -t, --timeout MS       Timeout in milliseconds (default: 1000)
  -V, --version          Print version and exit
  -h, --help             Show this help message
```

## Configuration File Format

The configuration file is a JSON file containing a list of Roughtime servers:

```json
{
  "servers": [
    {
      "name": "txryan-1",
      "version": "Google-Roughtime",
      "publicKeyType": "ed25519",
      "publicKey": "iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=",
      "addresses": [
        {
          "protocol": "udp",
          "address": "time.txryan.com:2002"
        }
      ]
    },
    {
      "name": "Netnod-sth1",
      "version": "IETF-Roughtime",
      "publicKeyType": "ed25519",
      "publicKey": "9l1JN4HakGnG44yyqyNNCb0HN0XfsysBbnl/kbZoZDc=",
      "addresses": [
        {
          "protocol": "udp",
          "address": "sth1.roughtime.netnod.se:2002"
        }
      ]
    },
    {
      "name": "Netnod-sth2",
      "version": "IETF-Roughtime",
      "publicKeyType": "ed25519",
      "publicKey": "T/xxX4ERUBAOpt64Z8phWamKsASZxJ0VWuiPm3GS/8g=",
      "addresses": [
        {
          "protocol": "udp",
          "address": "sth2.roughtime.netnod.se:2002"
        }
      ]
    }
  ]
}
```

## Library Usage

You can also use the Roughtime library in your own C++ projects:

```cpp
#include <roughtime/client.h>
#include <roughtime/config.h>
#include <iostream>

int main() {
    // Load configuration
    auto config = roughtime::load_config("servers.json");
    if (!config || config->servers.empty()) {
        std::cerr << "Failed to load config\n";
        return 1;
    }

    // Query servers
    roughtime::Client client;
    auto results = client.query_servers(config->servers);

    // Process results
    for (const auto& result : results) {
        if (result.is_success()) {
            std::cout << result.server->name << ": "
                     << "Midpoint: " << /* format time */
                     << " ±" << result.radius.count() << "s\n";
        } else {
            std::cerr << "Error: " << result.error << "\n";
        }
    }

    return 0;
}
```

Link against the library:

```cmake
target_link_libraries(your_app PRIVATE roughtime)
```

## Protocol Details

### Google-Roughtime

The original Roughtime protocol as specified by Google:
- **Nonce Size**: 64 bytes
- **Timestamp Format**: Unix microseconds since epoch
- **Hash Algorithm**: SHA-512 (64 bytes)
- **Merkle Tree**: 64-byte hashes
- **Framing**: No protocol framing

### IETF-Roughtime

The IETF standardized version of Roughtime (drafts 07, 08, 11, and 14):
- **Nonce Size**: 32 bytes
- **Timestamp Format**:
  - **Draft-07/08/11**: Modified Julian Date (MJD)
    - Top 24 bits: Days since November 17, 1858
    - Bottom 40 bits: Microseconds since midnight
    - Unix epoch (Jan 1, 1970) = MJD 40587
  - **Draft-14**: Unix seconds since epoch (simplified format)
- **Radius Precision**: Seconds (changed from microseconds in draft-14)
- **Hash Algorithm**: SHA-512/256 per FIPS 180-4 (32 bytes)
- **Merkle Tree**: 32-byte hashes
- **Framing**: "ROUGHTIM" header
- **Version Negotiation**: VER tag with supported versions
- **Server Identification**: SRV tag (draft-11+)

### Key Differences

| Feature | Google-Roughtime | IETF Draft-07/08/11 | IETF Draft-14 |
|---------|-----------------|---------------------|---------------|
| Nonce Size | 64 bytes | 32 bytes | 32 bytes |
| Timestamp | Unix microseconds | MJD (days + μs) | Unix seconds |
| Radius | Microseconds | Seconds | Seconds |
| Hash Function | SHA-512 | SHA-512/256 | SHA-512/256 |
| Merkle Hash Size | 64 bytes | 32 bytes | 32 bytes |
| Framing | None | "ROUGHTIM" | "ROUGHTIM" |
| Version Tag | Not used | VER tag | VER tag |
| Server Tag | Not used | SRV tag (draft-11) | SRV tag |
| Cert Context | 36 bytes (null-term) | 34/36 bytes (null-term) | 33 bytes (no null) |

## Security Considerations

- Always verify server public keys through secure channels
- Use multiple servers for time consensus
- Check the uncertainty radius (±) of returned times
- Consider network delay when evaluating results
- Implement proper timeout and retry logic

## Testing

The project includes a comprehensive test suite with 77 tests covering:

### Unit Tests
- **Protocol Tests** (16 tests): Message encoding/decoding, framing, version handling
- **Crypto Tests** (15 tests): SHA-512, SHA-512/256, Ed25519, Merkle trees

### Integration Tests
- **Client Integration** (8 tests): Real server communication, retries, chaining
- **Server Integration** (13 tests): Protocol support (all drafts), signatures, Merkle proofs, version negotiation
- **Rogue Server Tests** (10 tests): Security validation, attack resistance, multi-server consensus
- **Security Tests** (8 tests): Input validation, buffer safety, cryptographic correctness
- **Performance Tests** (7 tests): Throughput, latency, concurrency

### Continuous Integration
- **GitHub Actions CI**: Automated testing on every commit
  - Ubuntu 24.04 with Debug and Release builds
  - Sanitizer builds (ASan, UBSan) for memory leak detection
  - All 77 tests must pass before merge

### Running Tests

```bash
# Run all tests
cd build && ctest --output-on-failure

# Run specific test suites
ctest -R Protocol    # Protocol tests only
ctest -R Crypto      # Crypto tests only
ctest -R Performance # Performance tests only

# Verbose output
ctest -V
```

### Performance Benchmarks

The server performance tests measure:

- **Single-threaded**: ~3,500 requests/second
- **Concurrent (10 threads)**: ~13,000 requests/second
- **High concurrency (20 threads)**: ~10,000 requests/second
- **Burst load (50 threads)**: ~11,000 requests/second

Latency metrics:
- **Average**: <1ms
- **P50**: 0.3-0.6ms
- **P95**: 1-1.5ms
- **P99**: <5ms (typically <20ms under burst)

### Public Test Servers

**txryan:**
- Address: `time.txryan.com:2002`
- Public Key: `iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=`
- Version: Google-Roughtime

**Netnod (Sweden):**
- Address: `sth1.roughtime.netnod.se:2002`
- Public Key: `9l1JN4HakGnG44yyqyNNCb0HN0XfsysBbnl/kbZoZDc=`
- Version: IETF-Roughtime (draft-07)

**Cloudflare:**
- Address: `roughtime.cloudflare.com:2002`
- Public Key: `gD63hSj3ScS+wuOeGrubXlq35N1c5Lby/S+T7MNTjxo=`
- Version: IETF-Roughtime

## License

Copyright 2024

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## References

- [Roughtime Protocol (Google)](https://roughtime.googlesource.com/roughtime/+/HEAD/PROTOCOL.md)
- [draft-ietf-ntp-roughtime-14](https://datatracker.ietf.org/doc/html/draft-ietf-ntp-roughtime-14) (Latest - Active Internet-Draft)
- [draft-ietf-ntp-roughtime-11](https://datatracker.ietf.org/doc/html/draft-ietf-ntp-roughtime-11)
- [draft-ietf-ntp-roughtime-08](https://datatracker.ietf.org/doc/html/draft-ietf-ntp-roughtime-08)
- [draft-ietf-ntp-roughtime-07](https://datatracker.ietf.org/doc/html/draft-ietf-ntp-roughtime-07)
- [FIPS 180-4 (SHA-512/256)](https://csrc.nist.gov/publications/detail/fips/180/4/final)
- [Cloudflare's Go Implementation](https://github.com/cloudflare/roughtime)
- [Cloudflare Blog: Roughtime](https://blog.cloudflare.com/roughtime/)

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## Authors

Based on Cloudflare's Go implementation of Roughtime, ported to modern C++17.

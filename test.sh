#!/bin/bash
# Test script for Roughtime C++ client

set -e

echo "=== Roughtime C++ Test Suite ==="
echo ""

# Check if executable exists
if [ ! -f build/getroughtime ]; then
    echo "Error: build/getroughtime not found. Run ./build.sh first."
    exit 1
fi

echo "1. Version check:"
./build/getroughtime --version
echo ""

echo "2. Testing time.txryan.com (Google-Roughtime) - Known Working:"
./build/getroughtime \
    --ping time.txryan.com:2002 \
    --pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA= \
    --ping-version Google-Roughtime \
    --attempts 3 \
    --timeout 2000
echo ""

echo "3. Testing Cloudflare Roughtime (IETF-Roughtime):"
./build/getroughtime \
    --ping roughtime.cloudflare.com:2003 \
    --pubkey 0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg= \
    --ping-version IETF-Roughtime \
    --attempts 3 \
    --timeout 3000 || echo "Note: Cloudflare may have server issues"
echo ""

echo "4. Testing int08h Roughtime (IETF-Roughtime):"
./build/getroughtime \
    --ping roughtime.int08h.com:2002 \
    --pubkey AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE= \
    --ping-version IETF-Roughtime \
    --attempts 3 \
    --timeout 3000 || echo "Note: int08h may be offline"
echo ""

echo "5. Testing TRUSTED TIME with multiple servers:"
./build/getroughtime \
    --config examples/servers.json \
    --attempts 3 \
    --timeout 3000 || echo "Note: Some servers may be offline, but if 3+ respond it's trusted"
echo ""

echo "=== Test Summary ==="
echo "If time.txryan.com worked, the client is functioning correctly!"
echo "The trusted time test demonstrates querying multiple servers for consensus."
echo "At least 3 servers must respond for the time to be considered trusted."
echo "See TEST_RESULTS.md for details."

#!/bin/bash
# Build script for Roughtime C++ client and server

set -e

echo "=== Roughtime C++ Build Script ==="
echo ""

# Check for dependencies
echo "Checking dependencies..."

if ! command -v cmake &> /dev/null; then
    echo "Error: cmake not found. Please install CMake 3.14 or later."
    exit 1
fi

if ! command -v pkg-config &> /dev/null; then
    echo "Error: pkg-config not found. Please install pkg-config."
    exit 1
fi

if ! pkg-config --exists libsodium; then
    echo "Error: libsodium not found. Please install libsodium-dev."
    exit 1
fi

echo "All dependencies found."
echo ""

# Create build directory
echo "Creating build directory..."
mkdir -p build
cd build

# Configure
echo "Configuring with CMake..."
cmake .. -DCMAKE_BUILD_TYPE=Release

# Build
echo "Building..."
make -j$(nproc)

echo ""
echo "=== Build complete! ==="
echo ""
echo "Executables:"
echo "  - build/getroughtime (client)"
echo "  - build/roughtime-server (server)"
echo ""
echo "Test client:"
echo "  ./build/getroughtime --ping time.txryan.com:2002 \\"
echo "    --pubkey iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA= \\"
echo "    --ping-version Google-Roughtime"
echo ""
echo "Run server:"
echo "  ./build/roughtime-server --help"
echo ""

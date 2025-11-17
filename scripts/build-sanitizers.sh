#!/bin/bash
# Build and run tests with sanitizers (AddressSanitizer + UndefinedBehaviorSanitizer)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/build-sanitizers"

echo "=========================================="
echo "Building with Sanitizers"
echo "=========================================="

# Clean previous build
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Configure with sanitizers
cmake .. \
    -DCMAKE_BUILD_TYPE=Debug \
    -DENABLE_SANITIZERS=ON \
    -DBUILD_TESTS=ON

# Build
cmake --build . -j$(nproc)

echo ""
echo "=========================================="
echo "Running Tests with Sanitizers"
echo "=========================================="

# Run tests
export ASAN_OPTIONS=detect_leaks=1:check_initialization_order=1:strict_init_order=1
export UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1

ctest --output-on-failure

echo ""
echo "=========================================="
echo "Sanitizer Tests Completed Successfully!"
echo "=========================================="

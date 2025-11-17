#!/bin/bash
# Build and run tests with code coverage

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/build-coverage"
COVERAGE_DIR="$PROJECT_ROOT/coverage"

echo "=========================================="
echo "Building with Coverage"
echo "=========================================="

# Clean previous build
rm -rf "$BUILD_DIR" "$COVERAGE_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Configure with coverage
cmake .. \
    -DCMAKE_BUILD_TYPE=Debug \
    -DENABLE_COVERAGE=ON \
    -DBUILD_TESTS=ON

# Build
cmake --build . -j$(nproc)

echo ""
echo "=========================================="
echo "Running Tests"
echo "=========================================="

# Run tests
ctest --output-on-failure

echo ""
echo "=========================================="
echo "Generating Coverage Report"
echo "=========================================="

# Check if lcov is installed
if ! command -v lcov &> /dev/null; then
    echo "Warning: lcov not installed. Install with: sudo apt-get install lcov"
    echo "Skipping HTML report generation"
    exit 0
fi

# Generate coverage data
lcov --capture --directory . --output-file coverage.info

# Remove system and test files from coverage
lcov --remove coverage.info \
    '/usr/*' \
    '*/tests/*' \
    '*/build-coverage/*' \
    --output-file coverage_filtered.info

# Generate HTML report
mkdir -p "$COVERAGE_DIR"
genhtml coverage_filtered.info --output-directory "$COVERAGE_DIR"

# Print summary
lcov --summary coverage_filtered.info

echo ""
echo "=========================================="
echo "Coverage Report Generated!"
echo "=========================================="
echo "  HTML Report: $COVERAGE_DIR/index.html"
echo ""
echo "To view the report:"
echo "  firefox $COVERAGE_DIR/index.html"
echo "=========================================="

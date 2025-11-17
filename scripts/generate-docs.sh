#!/bin/bash
# Generate API documentation using Doxygen

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

echo "=========================================="
echo "Generating API Documentation"
echo "=========================================="

# Check if doxygen is installed
if ! command -v doxygen &> /dev/null; then
    echo "Error: doxygen not installed"
    echo "Install with: sudo apt-get install doxygen graphviz"
    exit 1
fi

# Check if dot (graphviz) is available
if ! command -v dot &> /dev/null; then
    echo "Warning: graphviz not installed - graphs will not be generated"
    echo "Install with: sudo apt-get install graphviz"
fi

# Generate documentation
doxygen Doxyfile

echo ""
echo "=========================================="
echo "Documentation Generated Successfully!"
echo "=========================================="
echo "  Output: docs/api/html/index.html"
echo ""
echo "To view:"
echo "  firefox docs/api/html/index.html"
echo "  or"
echo "  xdg-open docs/api/html/index.html"
echo "=========================================="

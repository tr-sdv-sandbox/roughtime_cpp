#!/bin/bash
set -e

echo "Roughtime C++ Dependency Installer"
echo "==================================="
echo ""

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
elif [ -f /etc/redhat-release ]; then
    OS="rhel"
elif [ "$(uname)" == "Darwin" ]; then
    OS="macos"
else
    echo "Unsupported operating system"
    exit 1
fi

echo "Detected OS: $OS"
echo ""

# Install dependencies based on OS
case $OS in
    ubuntu|debian)
        echo "Installing dependencies for Ubuntu/Debian..."
        sudo apt-get update
        sudo apt-get install -y \
            build-essential \
            cmake \
            pkg-config \
            libssl-dev \
            libgoogle-glog-dev \
            libgtest-dev \
            nlohmann-json3-dev
        echo "✓ Dependencies installed successfully"
        ;;
    
    fedora)
        echo "Installing dependencies for Fedora..."
        sudo dnf install -y \
            gcc-c++ \
            cmake \
            pkg-config \
            openssl-devel \
            glog-devel \
            gtest-devel \
            json-devel
        echo "✓ Dependencies installed successfully"
        ;;
    
    rhel|centos)
        echo "Installing dependencies for RHEL/CentOS..."
        # Enable EPEL for additional packages
        sudo dnf install -y epel-release || true
        sudo dnf install -y \
            gcc-c++ \
            cmake \
            pkg-config \
            openssl-devel \
            glog-devel \
            gtest-devel \
            json-devel
        echo "✓ Dependencies installed successfully"
        ;;
    
    arch|manjaro)
        echo "Installing dependencies for Arch Linux..."
        sudo pacman -Sy --noconfirm \
            base-devel \
            cmake \
            pkg-config \
            openssl \
            google-glog \
            gtest \
            nlohmann-json
        echo "✓ Dependencies installed successfully"
        ;;
    
    macos)
        echo "Installing dependencies for macOS..."
        # Check if Homebrew is installed
        if ! command -v brew &> /dev/null; then
            echo "Error: Homebrew is not installed"
            echo "Please install Homebrew from https://brew.sh/"
            exit 1
        fi

        brew install \
            cmake \
            pkg-config \
            openssl \
            glog \
            googletest \
            nlohmann-json
        echo "✓ Dependencies installed successfully"
        ;;
    
    *)
        echo "Unsupported OS: $OS"
        echo ""
        echo "Please install the following dependencies manually:"
        echo "  - C++17 compiler (GCC 7+ or Clang 5+)"
        echo "  - CMake 3.14+"
        echo "  - pkg-config"
        echo "  - OpenSSL"
        echo "  - glog"
        echo "  - GoogleTest"
        echo "  - nlohmann-json"
        exit 1
        ;;
esac

echo ""
echo "All dependencies installed!"
echo ""
echo "Next steps:"
echo "  1. mkdir build && cd build"
echo "  2. cmake -DCMAKE_BUILD_TYPE=Release .."
echo "  3. cmake --build . -j\$(nproc)"
echo "  4. ctest --output-on-failure"
echo ""

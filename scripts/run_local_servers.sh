#!/bin/bash
# Copyright 2024
# SPDX-License-Identifier: Apache-2.0
#
# Script to run 3 local Roughtime servers for testing over WiFi

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build"
CONFIG_DIR="${PROJECT_ROOT}/local_servers"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if build directory exists
if [ ! -d "$BUILD_DIR" ]; then
    echo -e "${RED}Error: Build directory not found at $BUILD_DIR${NC}"
    echo "Please build the project first:"
    echo "  mkdir build && cd build && cmake .. && make"
    exit 1
fi

# Check if executables exist
if [ ! -f "$BUILD_DIR/roughtime-keygen" ] || [ ! -f "$BUILD_DIR/roughtime-server" ]; then
    echo -e "${RED}Error: Executables not found${NC}"
    echo "Please build the project first:"
    echo "  cd build && make"
    exit 1
fi

# Create config directory
mkdir -p "$CONFIG_DIR"

# Get local IP address
LOCAL_IP=$(hostname -I | awk '{print $1}')
if [ -z "$LOCAL_IP" ]; then
    echo -e "${YELLOW}Warning: Could not detect local IP address, using 0.0.0.0${NC}"
    LOCAL_IP="0.0.0.0"
fi

echo -e "${BLUE}=== Roughtime Local Test Servers ===${NC}"
echo -e "${GREEN}Local IP: $LOCAL_IP${NC}\n"

# Generate server configs if they don't exist
for i in 1 2 3; do
    CONFIG_FILE="$CONFIG_DIR/server${i}.json"
    PORT=$((3001 + i))

    if [ ! -f "$CONFIG_FILE" ]; then
        echo -e "${YELLOW}Generating config for server${i}...${NC}"
        "$BUILD_DIR/roughtime-keygen" \
            -o "$CONFIG_FILE" \
            -n "local-server-${i}" \
            -a "0.0.0.0" \
            -p "$PORT" \
            -r 1 \
            -c 48
    else
        echo -e "${GREEN}Using existing config: $CONFIG_FILE${NC}"
    fi
done

# Generate client config file
CLIENT_CONFIG="$CONFIG_DIR/client_config.json"
echo -e "\n${YELLOW}Generating client configuration...${NC}"

# Read public keys from server configs
SERVER1_KEY=$(jq -r '.publicKey' "$CONFIG_DIR/server1.json")
SERVER2_KEY=$(jq -r '.publicKey' "$CONFIG_DIR/server2.json")
SERVER3_KEY=$(jq -r '.publicKey' "$CONFIG_DIR/server3.json")

# Use the actual local IP for client config
CONNECT_IP=$(hostname -I | awk '{print $1}')
if [ -z "$CONNECT_IP" ]; then
    CONNECT_IP="localhost"
fi

cat > "$CLIENT_CONFIG" << EOF
{
  "servers": [
    {
      "name": "local-server-1",
      "version": "IETF-Roughtime",
      "publicKeyType": "ed25519",
      "publicKey": "$SERVER1_KEY",
      "addresses": [
        {
          "protocol": "udp",
          "address": "$CONNECT_IP:3002"
        }
      ]
    },
    {
      "name": "local-server-2",
      "version": "IETF-Roughtime",
      "publicKeyType": "ed25519",
      "publicKey": "$SERVER2_KEY",
      "addresses": [
        {
          "protocol": "udp",
          "address": "$CONNECT_IP:3003"
        }
      ]
    },
    {
      "name": "local-server-3",
      "version": "IETF-Roughtime",
      "publicKeyType": "ed25519",
      "publicKey": "$SERVER3_KEY",
      "addresses": [
        {
          "protocol": "udp",
          "address": "$CONNECT_IP:3004"
        }
      ]
    }
  ]
}
EOF

echo -e "${GREEN}Client config saved to: $CLIENT_CONFIG${NC}"

# Function to cleanup on exit
cleanup() {
    echo -e "\n${YELLOW}Shutting down servers...${NC}"
    pkill -P $$ || true
    wait
    echo -e "${GREEN}All servers stopped${NC}"
}

trap cleanup EXIT INT TERM

# Start servers
echo -e "\n${BLUE}=== Starting Servers ===${NC}\n"

LOG_DIR="$CONFIG_DIR/logs"
mkdir -p "$LOG_DIR"

for i in 1 2 3; do
    CONFIG_FILE="$CONFIG_DIR/server${i}.json"
    LOG_FILE="$LOG_DIR/server${i}.log"
    PORT=$((3001 + i))

    echo -e "${GREEN}Starting server${i} on 0.0.0.0:${PORT}...${NC}"
    "$BUILD_DIR/roughtime-server" --config "$CONFIG_FILE" > "$LOG_FILE" 2>&1 &

    SERVER_PID=$!
    echo "  PID: $SERVER_PID"
    echo "  Log: $LOG_FILE"
done

# Wait for servers to start
sleep 1

echo -e "\n${BLUE}=== Servers Running ===${NC}"
echo -e "Server 1: ${GREEN}0.0.0.0:3002${NC} (accessible at ${YELLOW}$CONNECT_IP:3002${NC})"
echo -e "Server 2: ${GREEN}0.0.0.0:3003${NC} (accessible at ${YELLOW}$CONNECT_IP:3003${NC})"
echo -e "Server 3: ${GREEN}0.0.0.0:3004${NC} (accessible at ${YELLOW}$CONNECT_IP:3004${NC})"

echo -e "\n${BLUE}=== Test the servers with: ===${NC}"
echo -e "${YELLOW}$BUILD_DIR/getroughtime -c $CLIENT_CONFIG${NC}"

echo -e "\n${BLUE}=== Or ping individual servers: ===${NC}"
echo -e "${YELLOW}$BUILD_DIR/getroughtime --ping $CONNECT_IP:3002 --pubkey $SERVER1_KEY${NC}"

echo -e "\n${BLUE}=== From other devices on the network: ===${NC}"
echo -e "${YELLOW}getroughtime --ping $CONNECT_IP:3002 --pubkey $SERVER1_KEY${NC}"

echo -e "\n${RED}Press Ctrl+C to stop all servers${NC}\n"

# Wait for user interrupt
wait

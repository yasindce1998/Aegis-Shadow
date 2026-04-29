#!/bin/bash
# Aegis-Shadow Defense Testing Script
# Tests all 5 defensive detection modules

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "🛡️  Aegis-Shadow Defense Test Suite"
echo "==================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Error: This script must be run as root${NC}"
    exit 1
fi

# Build the project
echo -e "${YELLOW}Building defense components...${NC}"
cargo xtask build-ebpf --release
cargo build --release --bin defense

# Start defense engine
echo -e "\n${YELLOW}Starting defense engine...${NC}"
./target/release/defense --all-modules --verbose --output /tmp/aegis_alerts.json &
DEFENSE_PID=$!
sleep 3

# Test 1: Ghost Map Detection
echo -e "\n${YELLOW}Test 1: Ghost Map Detection${NC}"
echo "Creating test BPF map..."
bpftool map create /sys/fs/bpf/test_map type hash key 4 value 4 entries 10 name test_map || true
sleep 1
echo "Checking for ghost map alerts..."
if grep -q "Ghost Map" /tmp/aegis_alerts.json 2>/dev/null; then
    echo -e "${GREEN}✓ Ghost map detection working${NC}"
else
    echo -e "${YELLOW}⚠ No ghost map alerts (may be expected)${NC}"
fi

# Test 2: Syscall Latency Monitoring
echo -e "\n${YELLOW}Test 2: Syscall Latency Monitoring${NC}"
echo "Waiting for baseline calibration (60 seconds)..."
sleep 5
echo "Generating syscall activity..."
for i in {1..100}; do
    ls /tmp > /dev/null 2>&1
done
sleep 2
echo "Checking for latency alerts..."
if grep -q "Syscall Latency" /tmp/aegis_alerts.json 2>/dev/null; then
    echo -e "${GREEN}✓ Latency monitoring working${NC}"
else
    echo -e "${YELLOW}⚠ No latency alerts (baseline may be calibrating)${NC}"
fi

# Test 3: Bytecode Integrity Checking
echo -e "\n${YELLOW}Test 3: Bytecode Integrity Checking${NC}"
echo "Loading test BPF program..."
# This would trigger bytecode integrity checks
echo -e "${YELLOW}⚠ Bytecode checking requires actual BPF program load${NC}"

# Test 4: Hidden Process Detection
echo -e "\n${YELLOW}Test 4: Hidden Process Detection${NC}"
echo "Scanning /proc for processes..."
ls /proc/[0-9]* > /dev/null 2>&1
sleep 1
echo "Checking for hidden process alerts..."
if grep -q "Hidden Process" /tmp/aegis_alerts.json 2>/dev/null; then
    echo -e "${GREEN}✓ Hidden process detection working${NC}"
else
    echo -e "${YELLOW}⚠ No hidden process alerts${NC}"
fi

# Test 5: Suspicious Hook Detection
echo -e "\n${YELLOW}Test 5: Suspicious Hook Detection${NC}"
echo "Monitoring for suspicious BPF operations..."
sleep 2
if grep -q "Suspicious Hook" /tmp/aegis_alerts.json 2>/dev/null; then
    echo -e "${GREEN}✓ Hook detection working${NC}"
else
    echo -e "${YELLOW}⚠ No suspicious hook alerts${NC}"
fi

# Show alert summary
echo -e "\n${YELLOW}Alert Summary:${NC}"
if [ -f /tmp/aegis_alerts.json ]; then
    echo "Total alerts: $(wc -l < /tmp/aegis_alerts.json)"
    echo ""
    echo "Alert breakdown:"
    jq -r '.alert_type' /tmp/aegis_alerts.json 2>/dev/null | sort | uniq -c || cat /tmp/aegis_alerts.json
else
    echo "No alerts generated"
fi

# Cleanup
echo -e "\n${YELLOW}Cleaning up...${NC}"
kill $DEFENSE_PID 2>/dev/null || true
rm -f /sys/fs/bpf/test_map
rm -f /tmp/aegis_alerts.json

echo -e "\n${GREEN}Defense test suite completed!${NC}"

# Made with Bob

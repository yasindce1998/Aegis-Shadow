# Aegis-Shadow Architecture

## Overview

Aegis-Shadow is a dual-purpose eBPF-based security research platform implementing both offensive rootkit capabilities and defensive detection mechanisms. The architecture follows a modular design with clear separation between kernel-space eBPF programs and user-space control applications.

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     User Space                               │
├─────────────────────────────────────────────────────────────┤
│  Offense Loader          │         Defense Engine            │
│  ┌──────────────┐       │       ┌──────────────────┐       │
│  │ CLI Interface│       │       │ CLI Interface     │       │
│  │ Event Monitor│       │       │ DefenseEngine     │       │
│  │ C2 Handler   │       │       │  - Anomaly Scorer │       │
│  │ Kill Switch  │       │       │  - Chain Detector │       │
│  └──────────────┘       │       │  - Hot-Reload Cfg │       │
│                          │       │ JSON Logger       │       │
│                          │       └──────────────────┘       │
├─────────────────────────────────────────────────────────────┤
│                    eBPF Verifier                             │
├─────────────────────────────────────────────────────────────┤
│                     Kernel Space                             │
├─────────────────────────────────────────────────────────────┤
│  Offense eBPF Programs   │    Defense eBPF Programs         │
│  ┌──────────────┐       │       ┌──────────────┐           │
│  │ Kprobes      │       │       │ Tracepoints  │           │
│  │ Kretprobes   │       │       │ Kprobes      │           │
│  │ XDP          │       │       │ Perf Events  │           │
│  │ TC Classifier│       │       └──────────────┘           │
│  │ Tracepoints  │       │                                   │
│  └──────────────┘       │                                   │
├─────────────────────────────────────────────────────────────┤
│                    Linux Kernel                              │
└─────────────────────────────────────────────────────────────┘
```

## Technical Details

### eBPF Program Types Used
- **Kprobes/Kretprobes**: Dynamic kernel function tracing
- **XDP**: High-performance packet processing at driver level
- **TC Classifier**: Traffic control for egress packet manipulation
- **Tracepoints**: Static kernel instrumentation points

### BPF Map Types
- **HashMap**: Key-value storage for configuration and state
- **PerCpuHashMap**: Per-CPU latency tracking for defense
- **PerfEventArray**: High-performance event streaming to user-space

### Security Considerations
- All eBPF programs pass verifier checks
- No kernel memory corruption
- Bounded loops and stack usage
- CO-RE (Compile Once, Run Everywhere) for kernel compatibility

## Data Flow

### Offense Data Flow
```
User Command → Offense Loader → eBPF Maps → eBPF Programs → Kernel Hooks
                     ↑                                            ↓
                     └────────── PerfEventArray ←────────────────┘

C2 Ingress:  UDP:53 → XDP → MAGIC check → ChaCha20 decrypt → HMAC verify → Command Map
C2 Dispatch: Command Map → User-space → Execute (hide/unhide/obfuscate/exfil/kill)
```

### Defense Data Flow
```
Kernel Activity → eBPF Programs → Detection Logic → DefenseAlert
                                                          ↓
                                                   PerfEventArray
                                                          ↓
                                                   Defense Engine
                                                    ├─ Threshold Filter
                                                    ├─ Per-PID History
                                                    ├─ Anomaly Scoring (rate vs baseline)
                                                    ├─ Attack Chain Correlation
                                                    └─ Output
                                                        ├─ JSON Log
                                                        └─ Console
```

## Build System

The project uses a custom `xtask` build system:

1. **eBPF Compilation**: `cargo xtask build-ebpf`
   - Compiles to `bpfel-unknown-none` target
   - Uses `bpf-linker` for final linking
   - Generates BTF information

2. **User-Space Compilation**: `cargo build`
   - Embeds eBPF bytecode using `include_bytes_aligned!`
   - Links against `aya` runtime (~0.13)

### Workspace Members
| Crate | Purpose |
|---|---|
| `common` | Shared types and constants (`#![no_std]`) |
| `offense` | User-space rootkit loader |
| `offense-ebpf` | Kernel-space rootkit eBPF programs |
| `defense` | User-space detection engine + library |
| `defense-ebpf` | Kernel-space defensive eBPF probes |
| `xtask` | Build automation |
| `integration-tests` | Adversarial offense-vs-defense tests |

## Performance Characteristics

- **XDP**: ~10-20ns per packet processing
- **Kprobe overhead**: ~1-2us per invocation
- **Map lookup**: O(1) hash table operations
- **Event streaming**: Lock-free per-CPU ring buffers
- **Defense alert rate-limiting**: 100ms minimum interval per-CPU

## Compatibility

- **Kernel**: Linux 5.10+ (BTF required)
- **Architecture**: x86_64
- **Dependencies**: libbpf, clang, llvm

## Offensive Features (13 Total)

| # | Feature | Hook Point | Description |
|---|---|---|---|
| 1 | Process Hiding | kprobe: `__x64_sys_getdents64` | Filters directory entries to hide PIDs |
| 2 | Network Stealth | XDP on interface | C2 ingress with ChaCha20 + HMAC auth |
| 3 | File Obfuscation | kprobe: `vfs_read` | Zeros file contents for target inodes |
| 4 | Telemetry Muting | kprobe: `audit_log_start/end` | Suppresses audit events for rootkit PIDs |
| 5 | C2 Command & Control | (part of XDP) | Encrypted command channel over UDP:53 |
| 6 | Credential Harvesting | kprobe: `ksys_write` | Captures TTY writes (keystrokes) |
| 7 | Log Tampering | kprobe: `do_syslog` | Removes rootkit traces from kernel logs |
| 8 | Ancestry Spoofing | kprobe: `vfs_read` | Fakes parent PID in /proc/[pid]/status |
| 9 | DNS Exfiltration | TC egress classifier | Encodes data in DNS query labels |
| 10 | Kallsyms Hiding | kprobe: `vfs_read` | Removes symbols from /proc/kallsyms |
| 11 | Anti-Detach | tracepoint: `sys_enter_bpf` | Prevents BPF program removal |
| 12 | Map Persistence | bpffs pin | Pins maps to `/sys/fs/bpf/shadow` |
| 13 | Timestomping | kprobe: `vfs_getattr` | Fakes file atime/mtime/ctime |

### C2 Protocol

- **Transport**: UDP port 53 (disguised as DNS)
- **Encryption**: ChaCha20 (256-bit key, 96-bit nonce)
- **Authentication**: Truncated HMAC-SHA256 (16 bytes)
- **Packet format**: `[4B magic] [12B nonce] [16B encrypted payload] [16B HMAC]`
- **Commands**: hide_pid (1), unhide_pid (2), obfuscate_file (3), exfil (4), kill_switch (5)

## Defensive Modules (5 Total)

| # | Module | Hook Point | Detection Method |
|---|---|---|---|
| 1 | Ghost Map Detection | tracepoint: `sys_enter_bpf` | Identifies hidden/unauthorized BPF maps |
| 2 | Syscall Latency | tracepoint: `raw_syscalls/sys_enter+exit` | Detects hooking overhead via baseline comparison |
| 3 | Bytecode Integrity | tracepoint: `sys_enter_bpf` | Monitors BPF program loading for tampering |
| 4 | Hidden Process | kprobe: `__x64_sys_getdents64` | Cross-references /proc to detect hiding |
| 5 | Suspicious Hook | tracepoint: `sys_enter_bpf` | Alerts on unusual BPF attachments |

### DefenseEngine Intelligence

The user-space DefenseEngine provides advanced analysis beyond raw alert forwarding:

- **Calibration Phase**: Collects baseline alert rates during a configurable period (default 60s) before scoring begins
- **Anomaly Scoring**: Computes per-PID alert rate relative to calibrated baseline; scores >= 10.0 escalate severity to CRITICAL
- **Attack Chain Detection**: When a single PID triggers 3+ distinct alert types within a sliding window, the engine flags it as a correlated attack chain
- **Per-PID History**: Tracks alert timestamps and type bitmask per process in a sliding window (default 30s)
- **Hot-Reload Config**: Polls a JSON config file every 5 seconds to update threshold and window without restart
- **Metrics**: On shutdown, reports alerts_processed, alerts_suppressed, attack_chains_detected, anomaly_escalations, and per-type breakdown

### Runtime Configuration (Hot-Reload)

The defense engine accepts a `--config` path to a JSON file:

```json
{
  "threshold": 2,
  "window_secs": 30
}
```

Changes are picked up every 5 seconds without restarting the engine.

## Future Enhancements

- ARM64 support
- VM runtime test harness for automated integration testing
- Machine learning-based anomaly detection
- Distributed C2 infrastructure

# Aegis-Shadow Architecture

## Overview

Aegis-Shadow is a dual-purpose eBPF-based security research platform implementing both offensive rootkit capabilities and defensive detection mechanisms. The architecture follows a modular design with clear separation between kernel-space eBPF programs and user-space control applications.

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     User Space                               │
├─────────────────────────────────────────────────────────────┤
│  Offense Loader          │         Defense Engine            │
│  ┌──────────────┐       │       ┌──────────────┐           │
│  │ CLI Interface│       │       │ CLI Interface│           │
│  │ Event Monitor│       │       │ Alert Engine │           │
│  │ C2 Handler   │       │       │ JSON Logger  │           │
│  └──────────────┘       │       └──────────────┘           │
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
```

### Defense Data Flow
```
Kernel Activity → eBPF Programs → Detection Logic → DefenseAlert
                                                          ↓
                                                   PerfEventArray
                                                          ↓
                                                   Defense Engine
                                                          ↓
                                                   JSON Log / Console
```

## Build System

The project uses a custom `xtask` build system:

1. **eBPF Compilation**: `cargo xtask build-ebpf`
   - Compiles to `bpfel-unknown-none` target
   - Uses `bpf-linker` for final linking
   - Generates BTF information

2. **User-Space Compilation**: `cargo build`
   - Embeds eBPF bytecode using `include_bytes_aligned!`
   - Links against `aya` runtime

## Performance Characteristics

- **XDP**: ~10-20ns per packet processing
- **Kprobe overhead**: ~1-2μs per invocation
- **Map lookup**: O(1) hash table operations
- **Event streaming**: Lock-free ring buffer

## Compatibility

- **Kernel**: Linux 5.10+ (BTF required)
- **Architecture**: x86_64
- **Dependencies**: libbpf, clang, llvm

## Offensive Features (13 Total)

1. **Process Hiding**: Manipulates getdents64 to hide PIDs
2. **Network Stealth**: XDP-based C2 with encryption
3. **File Obfuscation**: Zeros file contents via vfs_read
4. **Telemetry Muting**: Suppresses audit events
5. **Credential Harvesting**: Captures TTY writes
6. **Log Tampering**: Removes rootkit traces from logs
7. **Process Ancestry Spoofing**: Fakes parent PID
8. **DNS Exfiltration**: Encodes data in DNS queries
9. **Kallsyms Hiding**: Removes symbols from /proc/kallsyms
10. **Anti-Detach**: Prevents BPF program removal
11. **ChaCha8 Encryption**: Encrypted C2 channel
12. **Timestomping**: Fakes file timestamps

## Defensive Modules (5 Total)

1. **Ghost Map Detection**: Identifies hidden BPF maps
2. **Syscall Latency Monitoring**: Detects hooking overhead
3. **Bytecode Integrity**: Monitors BPF program loading
4. **Hidden Process Detection**: Identifies process hiding
5. **Suspicious Hook Detection**: Alerts on unusual attachments

## Future Enhancements

- ARM64 support
- Additional detection modules
- Machine learning-based anomaly detection
- Distributed C2 infrastructure
- Enhanced encryption (ChaCha20-Poly1305)
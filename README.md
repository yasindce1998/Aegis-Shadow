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

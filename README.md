<div align="center">

![Aegis-Shadow Logo](assets/logo.svg)

[![License](https://img.shields.io/badge/license-Educational-red.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-nightly-orange.svg)](https://www.rust-lang.org/)
[![eBPF](https://img.shields.io/badge/eBPF-CO--RE-blue.svg)](https://ebpf.io/)
[![Kernel](https://img.shields.io/badge/kernel-5.10+-green.svg)](https://www.kernel.org/)

</div>

---

## Overview

Aegis-Shadow is an educational research project that demonstrates both offensive and
defensive uses of Linux eBPF technology. It consists of two modules:

- **Shadow** (Offense): An eBPF-based rootkit with 13 features including process hiding,
  XDP-based C2 with ChaCha20 encryption and HMAC authentication, file obfuscation,
  credential harvesting, DNS exfiltration, and timestomping.
- **Aegis** (Defense): A runtime detection engine with 5 eBPF-based detection modules
  plus intelligent user-space analysis including anomaly scoring, attack chain
  correlation, calibration-based baselines, and hot-reloadable configuration.

## Warning

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

# 3. Start offensive rootkit (loads all 13 features)
sudo ./target/release/offense --iface eth0 --hide-pid 1234

# 4. Run defense detection (in another terminal)
sudo ./target/release/defense --all-modules --verbose

# 5. Stop programs
# Press Ctrl+C in each terminal, or:
sudo pkill offense
sudo pkill defense
```

## Project Structure

| Directory | Purpose |
|---|---|
| `common/` | Shared data structures and constants (`#![no_std]`) |
| `offense-ebpf/` | Kernel-space rootkit eBPF programs |
| `offense/` | User-space rootkit loader and CLI |
| `defense-ebpf/` | Kernel-space defensive eBPF probes |
| `defense/` | User-space detection engine and CLI |
| `xtask/` | Build automation |
| `integration-tests/` | Adversarial offense-vs-defense test suite |

## Usage

### Offense (Rootkit)

The offense module loads **all 13 rootkit features automatically** on startup. Configure via optional flags:

```bash
# Basic usage - loads all features
sudo ./target/release/offense --iface eth0

# With optional configurations
sudo ./target/release/offense \
    --iface eth0 \
    --hide-pid 1234 \
    --obfuscate-inode 98765 \
    --monitor-tty 136:0 \
    --pin-maps
```

**Available flags:** `--iface`, `--verbose`, `--hide-pid`, `--obfuscate-inode`, `--monitor-tty`, `--spoof-ppid`, `--timestomp`, `--pin-maps`

### Defense (Detection Engine)

The defense module enables detection modules via flags and provides intelligent alert analysis:

```bash
# Enable all detection modules
sudo ./target/release/defense --all-modules

# Enable specific modules with hot-reload config
sudo ./target/release/defense \
    --ghost-maps \
    --syscall-latency \
    --bytecode-check \
    --config /etc/aegis/config.json \
    --output /tmp/alerts.json

# Custom calibration and threshold
sudo ./target/release/defense --all-modules \
    --threshold 3 \
    --calibration-period 120
```

**Available flags:** `--verbose`, `--output`, `--threshold`, `--all-modules`, `--ghost-maps`, `--syscall-latency`, `--bytecode-check`, `--hidden-process`, `--suspicious-hooks`, `--calibration-period`, `--config`

For detailed usage examples, see [USAGE.md](USAGE.md)

## Running Tests

```bash
# Run integration tests (user-space, no root required)
cargo test -p integration-tests

# Run automated test scripts (requires root, in VM)
sudo ./tests/test_offense.sh
sudo ./tests/test_defense.sh

# Or use Makefile
make test
```

For manual testing procedures, see [USAGE.md](USAGE.md#testing)

## License

This project is provided for educational purposes only. See Section 13 of the PRD
for full safety and legal guidelines.

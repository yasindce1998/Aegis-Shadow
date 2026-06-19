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
│  │ ICMP Exfil   │       │       │  - Chain Detector │       │
│  │ Cred Relay   │       │       │  - Correlation DAG│       │
│  │ Kill Switch  │       │       │  - Auto-Detach    │       │
│  └──────────────┘       │       │  - Auto-Contain   │       │
│                          │       │  - Honeypot Mgr   │       │
│                          │       │  - Hot-Reload Cfg │       │
│                          │       │  - ML Engine      │       │
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
- **Array**: Fixed-size configuration and flag storage

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

ICMP Exfil:  User-space → ICMP_EXFIL_QUEUE map → TC egress → ICMP echo-request w/ payload
Cred Relay:  TTY kprobe → CRED_EVENTS → User-space → encode → ICMP/DNS exfil
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
                                                    ├─ Correlation Graph (DAG)
                                                    ├─ Auto-Detach (malicious prog removal)
                                                    ├─ Auto-Contain (cgroup isolation)
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
| `verification` | Formal proofs (Kani) and detection coverage matrix |
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

## Offensive Features (88 Total, 12 Advanced Modules)

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
| 14 | Network Namespace Hiding | kprobe: `__x64_sys_setns` | Intercepts setns to hide namespaces |
| 15 | eBPF Program Cloaking | kprobe/kretprobe: `__x64_sys_bpf` | Hides own program IDs from enumeration |
| 16 | Kernel Module Masquerading | kprobe/kretprobe: `vfs_read` | Injects fake entries in /proc/modules |
| 17 | Memory-Only Payload Staging | kprobe: `memfd_create` + `execveat` | Fileless execution via memfd |
| 18 | Syslog Write Stripping | kprobe: `ksys_write` | Zeros log writes containing hidden PIDs |
| 19 | Anti-Forensics Bytecode Wipe | map flag | Programs become no-ops to evade analysis |
| 20 | ICMP Covert Channel | TC egress classifier | Exfiltrates data in ICMP echo payloads |
| 21 | Socket Cloning | kprobe: `tcp_sendmsg` | Shadows data on target connections |
| 22 | Credential Relay | user-space | Relays captured credentials over C2 |
| 23 | Container Escape Probes | kprobe: `unshare` + `commit_creds` | Detects container context and privilege escalation |

### Advanced Modules (F48-F75)

| # | Feature | Hook Point | Description |
|---|---|---|---|
| **Hypervisor Evasion** ||||
| 48 | Hypervisor Detection | kprobe: `kvm_emulate_cpuid` | CPUID-based hypervisor presence detection |
| 49 | Hypervisor Fingerprinting | kprobe: `kvm_hypercall` | Identify KVM/Xen/VMware/HyperV via hypercall patterns |
| 50 | Hypervisor Blind-Spot | kprobe: `exc_nmi` | Exploit NMI-based inspection gaps for covert action |
| 51 | Live Migration Detection | kprobe: `tsc_khz_changed` | Detect TSC rebase indicating VM live migration |
| **Polymorphic Engine** ||||
| 52 | Metamorphic Engine | kprobe: `bpf_prog_load` | Self-rewriting bytecode with rotating NOP-sled patterns |
| 53 | Pattern Rotation | kprobe: `__schedule` | Rotate instruction patterns via tail-call variant selection |
| 54 | Opaque Predicates | kprobe: `bpf_check` | Insert always-true runtime conditions to defeat static analysis |
| **Phantom Network Stack** ||||
| 55 | Phantom TCP Ingress | XDP on interface | Invisible SYN-ACK handling below kernel TCP stack |
| 56 | Phantom Connection State | kprobe: `tcp_rcv_state_process` | Full stateful phantom TCP connection tracking |
| 57 | Phantom Data Transfer | TC egress classifier | Inject/extract data via phantom connections |
| **Cross-Container Lateral Movement** ||||
| 58 | Cgroup BPF Injection | kprobe: `cgroup_bpf_prog_attach` | Inject eBPF programs into target container cgroups |
| 59 | Namespace Traversal | kprobe: `switch_task_namespaces` | Cross-container movement via namespace transitions |
| 60 | Namespace Escape | kprobe: `commit_creds` | Detect/exploit credential changes for container breakout |
| **DMA Covert Channels** ||||
| 61 | IOMMU Data Stashing | kprobe: `iommu_map` | Hide data in unused IOMMU page table entries |
| 62 | PCIe TLP Signaling | kprobe: `pci_read_config_dword` | Encode data in PCI config read patterns |
| 63 | NIC Firmware Exfil | kprobe: `ndo_start_xmit` | Inject exfil data in ethernet frame padding bytes |
| **Behavioral AI Camouflage** ||||
| 64 | Syscall Profiling | tracepoint: `raw_syscalls/sys_enter` | Build statistical baseline of system behavior |
| 65 | Activity Throttling | kprobe: `__schedule` | Throttle rootkit actions to avoid statistical anomalies |
| 66 | Norm Avoidance | kprobe: `__schedule` | Break timing patterns with randomized delays |
| **Supply Chain Persistence** ||||
| 67 | Package Manager Hook | kprobe: `do_execveat_common` | Monitor apt/yum/pip/npm/cargo executions |
| 68 | Binary Patching | kprobe: `vfs_read` | Modify binaries in-flight during package install |
| 69 | Integrity Bypass | kprobe: `security_file_open` | Override verification checks via bpf_override_return |
| **Dead Man's Switch** ||||
| 70 | Heartbeat Monitor | kprobe: `udp_rcv` | Monitor UDP heartbeat packets with magic marker |
| 71 | Dead Man's Arming | kprobe: `hrtimer_interrupt` | Periodic check for heartbeat timeout |
| 72 | Scorched Earth | kprobe: `vfs_unlink` | Evidence wipe triggered on heartbeat failure |
| **BPF Parasitism** ||||
| 73 | BPF Program Scanner | tracepoint: `syscalls/sys_enter_bpf` | Detect Falco/Tetragon/Cilium/Datadog programs |
| 74 | Tail-Call Injection | kprobe: `bpf_prog_array_copy` | Inject into target program's tail-call array |
| 75 | Prog Array Hijack | kprobe: `bpf_map_update_elem` | Replace security tool program FDs in prog arrays |
| **Advanced Kernel Object Manipulation** ||||
| 76 | task_struct Patching | kprobe: `__switch_to` | Modify process credentials/flags via direct task_struct access |
| 77 | LSM Hook Subversion | kprobe: `security_file_open` | Override LSM decisions with `bpf_override_return` |
| 78 | IDT Hooking | kprobe: `native_load_idt` | Monitor/shadow interrupt descriptor table modifications |
| 79 | ftrace Self-Hiding | kretprobe: `bpf_prog_get_info_by_id` | Filter own program IDs from bpftool enumeration |
| 80 | Kernel Live-Patch Abuse | kprobe: `klp_enable_patch` | Inject patches targeting security-relevant functions |
| **Network Stealth Layer** ||||
| 81 | Raw Socket C2 | XDP on interface | Port-coexistence C2 using magic markers in app-layer offset |
| 82 | TC Traffic Injection | TC egress classifier | Inject crafted response packets without user-space sockets |
| 83 | DNS-over-HTTPS C2 | kprobe: `tcp_sendmsg` | Domain-fronted C2 over TLS to CDN endpoints |
| 84 | Kernel Traffic Shaping | TC egress classifier | Rate-limit/jitter C2 traffic to mimic normal patterns |
| **Advanced Persistence** ||||
| 85 | Obfuscated BPF Pinning | kprobe: `bpf_obj_pin` | Time-seeded randomized pin paths under /sys/fs/bpf |
| 86 | Cgroup BPF Persistence | kprobe: `cgroup_bpf_prog_attach` | Attach to root cgroup for process-death survival |
| 87 | Module Parameter Injection | kprobe: `module_param_sysfs_setup` | Hide config in /sys/module/<legit>/parameters/ |
| 88 | initramfs Boot Loader | kprobe: `do_init_module` | Boot-time BPF loader via initramfs injection |

### C2 Protocol

- **Transport**: UDP port 53 (disguised as DNS)
- **Encryption**: ChaCha20 (256-bit key, 96-bit nonce)
- **Authentication**: Truncated HMAC-SHA256 (16 bytes)
- **Packet format**: `[4B magic] [12B nonce] [16B encrypted payload] [16B HMAC]`
- **Commands**: hide_pid (1), unhide_pid (2), obfuscate_file (3), exfil (4), kill_switch (5)

### ICMP Covert Channel

- **Egress**: TC classifier embeds exfil data in ICMP echo-request payloads (beyond standard 8-byte header)
- **Map**: `ICMP_EXFIL_QUEUE` (seq_num → IcmpExfilPayload with up to 56 bytes per packet)
- **User-space**: Queues credential captures and arbitrary data for ICMP exfiltration

## Defensive Modules (18 Total)

### Kernel-Space eBPF Detectors (15 Probes)

| # | Module | Hook Point | Detection Method |
|---|---|---|---|
| 1 | Ghost Map Detection | tracepoint: `sys_enter_bpf` | Identifies hidden/unauthorized BPF maps |
| 2 | Syscall Latency | tracepoint: `raw_syscalls/sys_enter+exit` | Detects hooking overhead via baseline comparison |
| 3 | Bytecode Integrity | tracepoint: `sys_enter_bpf` | Monitors BPF program loading for tampering |
| 4 | Hidden Process | kprobe: `__x64_sys_getdents64` | Cross-references /proc to detect hiding |
| 5 | Suspicious Hook | tracepoint: `sys_enter_bpf` | Alerts on unusual BPF attachments |
| 6 | Program Inventory | tracepoint: `sys_enter_bpf` | Detects prog ID gaps indicating cloaking |
| 7 | Syscall Anomaly | tracepoint: `raw_syscalls/sys_enter` | Profiles syscall argument patterns, flags novel hashes |
| 8 | Network Baseline | kprobe: `tcp_connect` | Per-PID port bitmask, alerts on new port categories |
| 9 | Memory-Backed Exec | kprobe: `memfd_create` + `execveat` | Detects fileless execution (memfd + AT_EMPTY_PATH) |
| 10 | Map Content Audit | tracepoint: `sys_enter_bpf` | Scans map updates for C2 signatures (magic bytes, known ports) |
| 11 | Tracepoint Coverage | kprobe: `bpf_prog_put` | Detects rapid program detach (anti-forensics wiping) |
| 12 | Cross-Reference Detection | tracepoint: `sched/sched_process_fork` | Cross-references PID creation vs /proc to find hidden processes |
| 13 | HW Performance Counters | kprobe: `perf_event_open` | Detects hook overhead via instruction/cache-miss ratio anomalies |
| 14 | Verifier Log Analysis | tracepoint: `syscalls/sys_enter_bpf` | Flags programs using dangerous helpers (probe_write, override_return) |
| 15 | Memory Forensics | kprobe: `schedule` | Periodic integrity checksums of kernel data structures (cred_jar, task list) |

### User-Space Response Modules (3 Modules)

| # | Module | Mechanism | Description |
|---|---|---|---|
| 12 | Auto-Detach | `bpf(BPF_PROG_DETACH)` | Automatically detaches programs with 3+ corroborating alerts |
| 13 | Process Containment | cgroup isolation | Moves attack-chain PIDs to restrictive cgroups |
| 14 | Honeypot Maps | pinned decoy maps | Creates enticing maps (`shadow_config`, `rootkit_pids`); alerts on any access |

### DefenseEngine Intelligence

The user-space DefenseEngine provides advanced analysis beyond raw alert forwarding:

- **Calibration Phase**: Collects baseline alert rates during a configurable period (default 60s) before scoring begins
- **Anomaly Scoring**: Computes per-PID alert rate relative to calibrated baseline; scores >= 10.0 escalate severity to CRITICAL
- **Attack Chain Detection**: When a single PID triggers 3+ distinct alert types within a sliding window, the engine flags it as a correlated attack chain
- **Correlation Graph (DAG)**: Nodes = alerts, edges = same-PID / parent-child / temporal proximity. Connected components with 3+ nodes identify attack chains
- **Per-PID History**: Tracks alert timestamps and type bitmask per process in a sliding window (default 30s)
- **Hot-Reload Config**: Polls a JSON config file every 5 seconds to update threshold and window without restart
- **Metrics**: On shutdown, reports alerts_processed, alerts_suppressed, attack_chains_detected, anomaly_escalations, and per-type breakdown

### Adversarial ML Detection Layer

Optional module (`--enable-ml`) providing machine-learning-based evasion resistance:

- **Syscall Sequence Model**: N-gram model (n=3..5) trained during calibration; detects novel syscall sequences not seen in baseline
- **Deviation Scoring**: Log-likelihood scoring against trained model; sequences exceeding 3σ from mean escalate alert severity
- **Evasion-Resistant Signatures**: Extracts invariant opcode-sequence patterns from observed BPF programs, ignoring register operands and NOP sleds

### Formal Verification (`verification` crate)

The verification crate provides mathematical guarantees about detection correctness:

- **Kani Proofs**: `#[kani::proof]` functions proving no false negatives for ghost map detection, latency anomaly detection, hidden process detection, and bytecode tamper detection
- **Detection Coverage Matrix**: Maps all 88 offense techniques to their detecting defense modules with confidence scores; identifies coverage gaps
- **Alert Completeness**: Proves all `ALERT_*` constants have corresponding handlers in the engine

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
- Distributed C2 infrastructure
- GPU-accelerated ML inference for real-time classification
- Coverage-guided fuzzing of detection gaps

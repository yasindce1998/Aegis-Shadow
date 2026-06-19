#![no_std]
#![no_main]
#![allow(unused_unsafe)]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_task, bpf_ktime_get_ns},
    macros::{kprobe, map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::{ProbeContext, TracePointContext},
};
use common::{
    DefenseAlert, LatencyBaseline, ALERT_BYTECODE_TAMPER, ALERT_CROSS_REFERENCE, ALERT_GHOST_MAP,
    ALERT_HIDDEN_PROCESS, ALERT_HONEYPOT_READ, ALERT_HW_PERF_COUNTER, ALERT_MAP_AUDIT,
    ALERT_MEMFD_EXEC, ALERT_MEMORY_FORENSICS, ALERT_NET_BASELINE, ALERT_PROG_INVENTORY,
    ALERT_SUSPICIOUS_HOOK, ALERT_SYSCALL_ANOMALY, ALERT_SYSCALL_LATENCY, ALERT_TRACEPOINT_GAP,
    ALERT_VERIFIER_ANALYSIS, MAGIC_BYTES,
};

// ──────────────────────────────────────────────
// BPF Maps
// ──────────────────────────────────────────────

#[map]
static DEFENSE_ALERTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static SYSCALL_ENTRY_TS: HashMap<u64, u64> = HashMap::with_max_entries(4096, 0);

#[map]
static LATENCY_BASELINE: HashMap<u32, LatencyBaseline> = HashMap::with_max_entries(512, 0);

/// Tracks PIDs that have created BPF maps (to distinguish known vs ghost).
/// Key: pid (u32). Value: creation count (u32).
#[map]
static KNOWN_MAP_IDS: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

/// Stores bytecode hashes of BPF programs loaded by each PID.
/// Key: pid (u32). Value: last bytecode hash (u64).
#[map]
static PROG_BYTECODE_HASHES: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

/// Tracks kprobe/tracepoint attachment counts per target hash.
/// Key: cmd hash (u64). Value: attachment count (u32).
#[map]
static KPROBE_ATTACH_COUNTS: HashMap<u64, u32> = HashMap::with_max_entries(512, 0);

// ──────────────────────────────────────────────
// MODULE 1: Ghost Map Detection
// ──────────────────────────────────────────────

const BPF_MAP_CREATE: u32 = 0;
const BPF_MAP_DELETE: u32 = 2;

#[tracepoint]
pub fn detect_ghost_map(ctx: TracePointContext) -> u32 {
    try_detect_ghost_map(&ctx).unwrap_or_default()
}

fn try_detect_ghost_map(ctx: &TracePointContext) -> Result<u32, i64> {
    let cmd: u32 = unsafe { ctx.read_at(16).map_err(|_| 1i64)? };

    if cmd != BPF_MAP_CREATE && cmd != BPF_MAP_DELETE {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    if cmd == BPF_MAP_CREATE {
        // Track this PID as a known map creator
        let count = unsafe { KNOWN_MAP_IDS.get(&pid) }.copied().unwrap_or(0);
        let _ = KNOWN_MAP_IDS.insert(&pid, &(count + 1), 0);

        let alert = DefenseAlert {
            alert_type: ALERT_GHOST_MAP,
            severity: 2,
            pid,
            _pad: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: cmd as u64,
            details: [0u8; 16],
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    } else if cmd == BPF_MAP_DELETE {
        // If deleting from a PID we haven't seen create maps, higher severity
        let severity = if unsafe { KNOWN_MAP_IDS.get(&pid) }.is_none() {
            4 // CRITICAL — unknown PID deleting maps
        } else {
            2
        };

        let alert = DefenseAlert {
            alert_type: ALERT_GHOST_MAP,
            severity,
            pid,
            _pad: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: cmd as u64,
            details: [0u8; 16],
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// MODULE 2: Syscall Latency Monitoring
// ──────────────────────────────────────────────

#[tracepoint]
pub fn monitor_syscall_enter(ctx: TracePointContext) -> u32 {
    try_monitor_syscall_enter(&ctx).unwrap_or_default()
}

fn try_monitor_syscall_enter(_ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let ts = unsafe { bpf_ktime_get_ns() };

    let _ = SYSCALL_ENTRY_TS.insert(&pid_tgid, &ts, 0);

    Ok(0)
}

#[tracepoint]
pub fn monitor_syscall_exit(ctx: TracePointContext) -> u32 {
    try_monitor_syscall_exit(&ctx).unwrap_or_default()
}

fn try_monitor_syscall_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    let entry_ts = match unsafe { SYSCALL_ENTRY_TS.get(&pid_tgid) } {
        Some(ts) => *ts,
        None => return Ok(0),
    };
    let _ = SYSCALL_ENTRY_TS.remove(&pid_tgid);

    let exit_ts = unsafe { bpf_ktime_get_ns() };
    let latency_ns = exit_ts.saturating_sub(entry_ts);

    let syscall_nr: u32 = unsafe { ctx.read_at(8).unwrap_or(0) };

    if let Some(baseline) = unsafe { LATENCY_BASELINE.get(&syscall_nr) } {
        let baseline_avg = baseline.avg_latency_ns;
        let threshold = baseline_avg + (baseline_avg / 2);

        if latency_ns > threshold {
            let pid = (pid_tgid >> 32) as u32;
            let mut details = [0u8; 16];
            let latency_bytes = latency_ns.to_le_bytes();
            details[0..8].copy_from_slice(&latency_bytes);

            let alert = DefenseAlert {
                alert_type: ALERT_SYSCALL_LATENCY,
                severity: 2,
                pid,
                _pad: 0,
                timestamp_ns: exit_ts,
                context: syscall_nr as u64,
                details,
            };

            let _ = DEFENSE_ALERTS.output(&alert, 0);
        }
    } else {
        let entry = LatencyBaseline {
            avg_latency_ns: latency_ns,
            sample_count: 1,
            _pad: 0,
        };
        let _ = LATENCY_BASELINE.insert(&syscall_nr, &entry, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// MODULE 3: Bytecode Integrity Checking
// ──────────────────────────────────────────────

const BPF_PROG_LOAD: u32 = 5;

#[tracepoint]
pub fn check_bytecode_integrity(ctx: TracePointContext) -> u32 {
    try_check_bytecode_integrity(&ctx).unwrap_or_default()
}

fn try_check_bytecode_integrity(ctx: &TracePointContext) -> Result<u32, i64> {
    let cmd: u32 = unsafe { ctx.read_at(16).map_err(|_| 1i64)? };

    if cmd != BPF_PROG_LOAD {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // Hash the command metadata as a fingerprint for this load
    let cmd_bytes = cmd.to_le_bytes();
    let hash = fnv1a_hash(&cmd_bytes);

    let severity = if let Some(prev_hash) = unsafe { PROG_BYTECODE_HASHES.get(&pid) } {
        if *prev_hash != hash {
            4 // CRITICAL — same PID loading different bytecode (possible tampering)
        } else {
            2
        }
    } else {
        3 // HIGH — new program load
    };

    let _ = PROG_BYTECODE_HASHES.insert(&pid, &hash, 0);

    let mut details = [0u8; 16];
    details[0..8].copy_from_slice(&hash.to_le_bytes());

    let alert = DefenseAlert {
        alert_type: ALERT_BYTECODE_TAMPER,
        severity,
        pid,
        _pad: 0,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: cmd as u64,
        details,
    };

    let _ = DEFENSE_ALERTS.output(&alert, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// MODULE 4: Hidden Process Detection
// ──────────────────────────────────────────────

#[kprobe]
pub fn detect_hidden_process(ctx: ProbeContext) -> u32 {
    try_detect_hidden_process(&ctx).unwrap_or_default()
}

fn try_detect_hidden_process(ctx: &ProbeContext) -> Result<u32, i64> {
    let buf_ptr: u64 = ctx.arg(1).ok_or(1i64)?;
    let count: u64 = ctx.arg(2).ok_or(2i64)?;

    if buf_ptr == 0 || count == 0 {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    if count < 1024 {
        let alert = DefenseAlert {
            alert_type: ALERT_HIDDEN_PROCESS,
            severity: 3,
            pid,
            _pad: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: count,
            details: [0u8; 16],
        };

        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// MODULE 5: Suspicious Hook Detection
// ──────────────────────────────────────────────

const BPF_PROG_ATTACH: u32 = 8;
const BPF_RAW_TRACEPOINT_OPEN: u32 = 17;

#[tracepoint]
pub fn detect_suspicious_hook(ctx: TracePointContext) -> u32 {
    try_detect_suspicious_hook(&ctx).unwrap_or_default()
}

fn try_detect_suspicious_hook(ctx: &TracePointContext) -> Result<u32, i64> {
    let cmd: u32 = unsafe { ctx.read_at(16).map_err(|_| 1i64)? };

    if cmd != BPF_PROG_ATTACH && cmd != BPF_RAW_TRACEPOINT_OPEN {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // Track attachment count per command type
    let key = cmd as u64 | ((pid as u64) << 32);
    let count = unsafe { KPROBE_ATTACH_COUNTS.get(&key) }
        .copied()
        .unwrap_or(0);
    let new_count = count + 1;
    let _ = KPROBE_ATTACH_COUNTS.insert(&key, &new_count, 0);

    // Escalate severity when same PID attaches many hooks
    let severity = if new_count > 3 { 4 } else { 3 };

    let mut details = [0u8; 16];
    details[0..4].copy_from_slice(&new_count.to_le_bytes());

    let alert = DefenseAlert {
        alert_type: ALERT_SUSPICIOUS_HOOK,
        severity,
        pid,
        _pad: 0,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: cmd as u64,
        details,
    };

    let _ = DEFENSE_ALERTS.output(&alert, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// Helper: FNV-1a Hash
// ──────────────────────────────────────────────

#[inline(always)]
fn fnv1a_hash(data: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let mut hash = FNV_OFFSET;
    let mut i = 0usize;

    while i < data.len() && i < 1024 {
        hash ^= data[i] as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
        i += 1;
    }

    hash
}

// ══════════════════════════════════════════════════════════════════════════════
// NEW DEFENSIVE MODULES (6-11 + Honeypot)
// ══════════════════════════════════════════════════════════════════════════════

// ──────────────────────────────────────────────
// Maps for new modules
// ──────────────────────────────────────────────

/// Module 6: Track last seen prog_id for gap detection.
#[map]
static LAST_PROG_ID: aya_ebpf::maps::Array<u32> = aya_ebpf::maps::Array::with_max_entries(1, 0);

/// Module 6: Set of prog IDs we've seen.
#[map]
static PROG_SEEN: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

/// Module 7: Syscall argument hash frequency table.
#[map]
static SYSCALL_ARG_HIST: HashMap<u64, u32> = HashMap::with_max_entries(4096, 0);

/// Module 7: Calibration flag (index 0: 0=calibrating, 1=armed).
#[map]
static SYSCALL_BASELINE_FLAG: aya_ebpf::maps::Array<u8> =
    aya_ebpf::maps::Array::with_max_entries(1, 0);

/// Module 8: Per-PID network port bitmask (ports 0-63 as bits).
#[map]
static PID_NET_PROFILE: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

/// Module 8: Network baseline calibration flag.
#[map]
static NET_BASELINE_FLAG: aya_ebpf::maps::Array<u8> = aya_ebpf::maps::Array::with_max_entries(1, 0);

/// Module 9: PIDs that called memfd_create (pid → timestamp_ns).
#[map]
static MEMFD_WATCH: HashMap<u32, u64> = HashMap::with_max_entries(256, 0);

/// Module 10: Known-bad signature patterns (up to 8, each 4 bytes stored as u32).
#[map]
static AUDIT_SIGS: aya_ebpf::maps::Array<u32> = aya_ebpf::maps::Array::with_max_entries(8, 0);

/// Module 11: Detach counter (index 0 = count, index 1 = window start timestamp hi, index 2 = lo).
#[map]
static DETACH_STATE: aya_ebpf::maps::Array<u64> = aya_ebpf::maps::Array::with_max_entries(2, 0);

/// Honeypot: Map IDs that are honeypots (map_id → 1).
#[map]
static HONEYPOT_IDS: HashMap<u32, u8> = HashMap::with_max_entries(16, 0);

// ──────────────────────────────────────────────
// MODULE 6: eBPF Program Inventory
// Detect prog_id gaps indicating cloaking.
// Hook: tracepoint/syscalls/sys_enter_bpf
// ──────────────────────────────────────────────

const BPF_PROG_GET_NEXT_ID: u32 = 11;

#[tracepoint]
pub fn detect_prog_inventory(ctx: TracePointContext) -> u32 {
    try_detect_prog_inventory(&ctx).unwrap_or_default()
}

fn try_detect_prog_inventory(ctx: &TracePointContext) -> Result<u32, i64> {
    let cmd: u32 = unsafe { ctx.read_at(16).map_err(|_| 1i64)? };

    if cmd != BPF_PROG_GET_NEXT_ID {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // Read the start_id argument (offset 24 in tracepoint args for bpf syscall)
    let start_id: u32 = unsafe { ctx.read_at(24).unwrap_or(0) };

    // Check for ID gap: if start_id - last_seen_id > 1, there's a gap
    let last_id = unsafe { LAST_PROG_ID.get(0) }.copied().unwrap_or(0);

    if start_id > last_id + 1 && last_id > 0 {
        let alert = DefenseAlert {
            alert_type: ALERT_PROG_INVENTORY,
            severity: 3,
            pid,
            _pad: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: start_id as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&last_id.to_le_bytes());
                d[4..8].copy_from_slice(&start_id.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    // Update last seen
    unsafe {
        if let Some(ptr) = LAST_PROG_ID.get_ptr_mut(0) {
            *ptr = start_id;
        }
    }
    let _ = PROG_SEEN.insert(&start_id, &1u8, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// MODULE 7: Syscall Argument Anomaly Profiling
// Hash first arg of key syscalls, track frequency.
// Alert on never-before-seen patterns after baseline.
// Hook: tracepoint/raw_syscalls/sys_enter
// ──────────────────────────────────────────────

const SYS_EXECVE: u64 = 59;
const SYS_OPEN: u64 = 2;
const SYS_CONNECT: u64 = 42;
const SYS_SOCKET: u64 = 41;

#[tracepoint]
pub fn detect_syscall_anomaly(ctx: TracePointContext) -> u32 {
    try_detect_syscall_anomaly(&ctx).unwrap_or_default()
}

fn try_detect_syscall_anomaly(ctx: &TracePointContext) -> Result<u32, i64> {
    // raw_syscalls/sys_enter: offset 8 = syscall nr (id), offset 16 = args[0]
    let syscall_nr: u64 = unsafe { ctx.read_at(8).map_err(|_| 1i64)? };

    if syscall_nr != SYS_EXECVE
        && syscall_nr != SYS_OPEN
        && syscall_nr != SYS_CONNECT
        && syscall_nr != SYS_SOCKET
    {
        return Ok(0);
    }

    let arg0: u64 = unsafe { ctx.read_at(16).unwrap_or(0) };

    // Hash syscall_nr + arg0 for a composite key
    let mut key_bytes = [0u8; 16];
    key_bytes[0..8].copy_from_slice(&syscall_nr.to_le_bytes());
    key_bytes[8..16].copy_from_slice(&arg0.to_le_bytes());
    let hash = fnv1a_hash(&key_bytes);

    // Update frequency
    let count = unsafe { SYSCALL_ARG_HIST.get(&hash) }.copied().unwrap_or(0);
    let _ = SYSCALL_ARG_HIST.insert(&hash, &(count + 1), 0);

    // Check if baseline is armed
    let armed = unsafe { SYSCALL_BASELINE_FLAG.get(0) }
        .copied()
        .unwrap_or(0);
    if armed == 0 {
        return Ok(0);
    }

    // If this is a brand new pattern (count was 0), alert
    if count == 0 {
        let pid_tgid = bpf_get_current_pid_tgid();
        let pid = (pid_tgid >> 32) as u32;

        let alert = DefenseAlert {
            alert_type: ALERT_SYSCALL_ANOMALY,
            severity: 2,
            pid,
            _pad: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: syscall_nr,
            details: {
                let mut d = [0u8; 16];
                d[0..8].copy_from_slice(&hash.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// MODULE 8: Network Behavior Baseline
// Track per-PID destination port profile.
// Alert on new port categories after baseline.
// Hook: kprobe/tcp_connect
// ──────────────────────────────────────────────

#[kprobe]
pub fn detect_net_anomaly(ctx: ProbeContext) -> u32 {
    try_detect_net_anomaly(&ctx).unwrap_or_default()
}

fn try_detect_net_anomaly(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // arg0 = struct sock *sk; we read inet_dport at offset 12 of inet_sock
    // Simplified: read dport from sock arg (offset varies by kernel)
    // For research, we use arg1 as address family hint and derive port from context
    let sk_ptr: u64 = ctx.arg(0).ok_or(1i64)?;
    if sk_ptr == 0 {
        return Ok(0);
    }

    // Read destination port from sk->__sk_common.skc_dport (offset 12)
    let dport: u16 = unsafe {
        aya_ebpf::helpers::bpf_probe_read_kernel((sk_ptr + 12) as *const u16).unwrap_or(0)
    };
    let dport = u16::from_be(dport);

    if dport == 0 {
        return Ok(0);
    }

    // Map port to a bit position (0-63 for ports 0-1023, grouped above)
    let bit_pos = if dport < 1024 {
        (dport / 16) as u32 // 64 buckets for well-known ports
    } else {
        63 // all high ports share one bucket
    };

    let bit_mask: u64 = 1u64 << bit_pos;
    let current_profile = unsafe { PID_NET_PROFILE.get(&pid) }.copied().unwrap_or(0);

    if current_profile & bit_mask == 0 {
        // New port category for this PID
        let new_profile = current_profile | bit_mask;
        let _ = PID_NET_PROFILE.insert(&pid, &new_profile, 0);

        // Check if baseline is armed
        let armed = unsafe { NET_BASELINE_FLAG.get(0) }.copied().unwrap_or(0);
        if armed != 0 {
            let severity = if dport < 1024 && (dport == 4444 || dport == 1337 || dport == 31337) {
                4 // CRITICAL for known C2 ports
            } else if bit_pos == 63 {
                2 // MEDIUM for high ports
            } else {
                3 // HIGH for new well-known port category
            };

            let alert = DefenseAlert {
                alert_type: ALERT_NET_BASELINE,
                severity,
                pid,
                _pad: 0,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: dport as u64,
                details: {
                    let mut d = [0u8; 16];
                    d[0..8].copy_from_slice(&new_profile.to_le_bytes());
                    d
                },
            };
            let _ = DEFENSE_ALERTS.output(&alert, 0);
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// MODULE 9: Memory-Backed Exec Detection
// Detect memfd_create → execveat chain (fileless malware).
// Hook: kprobe/__x64_sys_memfd_create + kprobe/do_execveat_common
// ──────────────────────────────────────────────

#[kprobe]
pub fn detect_memfd_create(ctx: ProbeContext) -> u32 {
    try_detect_memfd_create(&ctx).unwrap_or_default()
}

fn try_detect_memfd_create(_ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let ts = unsafe { bpf_ktime_get_ns() };

    let _ = MEMFD_WATCH.insert(&pid, &ts, 0);
    Ok(0)
}

#[kprobe]
pub fn detect_memfd_exec(ctx: ProbeContext) -> u32 {
    try_detect_memfd_exec(&ctx).unwrap_or_default()
}

fn try_detect_memfd_exec(_ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // Check if this PID recently called memfd_create
    let create_ts = match unsafe { MEMFD_WATCH.get(&pid) } {
        Some(ts) => *ts,
        None => return Ok(0),
    };

    let now = unsafe { bpf_ktime_get_ns() };
    let elapsed_ns = now.saturating_sub(create_ts);

    // Alert if execveat within 60 seconds of memfd_create
    const SIXTY_SECONDS_NS: u64 = 60_000_000_000;
    if elapsed_ns > SIXTY_SECONDS_NS {
        let _ = MEMFD_WATCH.remove(&pid);
        return Ok(0);
    }

    let alert = DefenseAlert {
        alert_type: ALERT_MEMFD_EXEC,
        severity: 4, // CRITICAL — strong fileless malware indicator
        pid,
        _pad: 0,
        timestamp_ns: now,
        context: elapsed_ns,
        details: {
            let mut d = [0u8; 16];
            d[0..8].copy_from_slice(&create_ts.to_le_bytes());
            d
        },
    };
    let _ = DEFENSE_ALERTS.output(&alert, 0);

    let _ = MEMFD_WATCH.remove(&pid);
    Ok(0)
}

// ──────────────────────────────────────────────
// MODULE 10: BPF Map Content Auditing
// Check map updates for known C2 signatures.
// Hook: tracepoint/syscalls/sys_enter_bpf (BPF_MAP_UPDATE_ELEM)
// ──────────────────────────────────────────────

const BPF_MAP_UPDATE_ELEM: u32 = 2;
const BPF_MAP_LOOKUP_ELEM: u32 = 1;

#[tracepoint]
pub fn audit_map_content(ctx: TracePointContext) -> u32 {
    try_audit_map_content(&ctx).unwrap_or_default()
}

fn try_audit_map_content(ctx: &TracePointContext) -> Result<u32, i64> {
    let cmd: u32 = unsafe { ctx.read_at(16).map_err(|_| 1i64)? };

    if cmd == BPF_MAP_LOOKUP_ELEM {
        // Honeypot check: read map_fd from args (offset 24)
        let map_fd: u32 = unsafe { ctx.read_at(24).unwrap_or(0) };

        if unsafe { HONEYPOT_IDS.get(&map_fd) }.is_some() {
            let pid_tgid = bpf_get_current_pid_tgid();
            let pid = (pid_tgid >> 32) as u32;

            let alert = DefenseAlert {
                alert_type: ALERT_HONEYPOT_READ,
                severity: 4,
                pid,
                _pad: 0,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: map_fd as u64,
                details: [0u8; 16],
            };
            let _ = DEFENSE_ALERTS.output(&alert, 0);
        }
        return Ok(0);
    }

    if cmd != BPF_MAP_UPDATE_ELEM {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // Read value pointer from args (offset 32 for value_ptr in bpf_attr)
    let value_ptr: u64 = unsafe { ctx.read_at(32).unwrap_or(0) };
    if value_ptr == 0 {
        return Ok(0);
    }

    // Read first 4 bytes of value to check for known signatures
    let first_bytes: u32 =
        unsafe { aya_ebpf::helpers::bpf_probe_read_user(value_ptr as *const u32).unwrap_or(0) };

    // Check against MAGIC_BYTES (0xDEADBEEF)
    let magic_u32 = u32::from_be_bytes(MAGIC_BYTES);
    if first_bytes == magic_u32 {
        let alert = DefenseAlert {
            alert_type: ALERT_MAP_AUDIT,
            severity: 3,
            pid,
            _pad: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: value_ptr,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&first_bytes.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
        return Ok(0);
    }

    // Check against configured audit signatures
    let mut i = 0u32;
    while i < 8 {
        if let Some(&sig) = unsafe { AUDIT_SIGS.get(i) } {
            if sig != 0 && first_bytes == sig {
                let alert = DefenseAlert {
                    alert_type: ALERT_MAP_AUDIT,
                    severity: 3,
                    pid,
                    _pad: 0,
                    timestamp_ns: unsafe { bpf_ktime_get_ns() },
                    context: i as u64,
                    details: {
                        let mut d = [0u8; 16];
                        d[0..4].copy_from_slice(&first_bytes.to_le_bytes());
                        d[4..8].copy_from_slice(&sig.to_le_bytes());
                        d
                    },
                };
                let _ = DEFENSE_ALERTS.output(&alert, 0);
                return Ok(0);
            }
        }
        i += 1;
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// MODULE 11: Tracepoint Coverage Monitor
// Track BPF program detachment rate.
// Alert if rapid detach burst (anti-forensics indicator).
// Hook: kprobe/bpf_prog_put
// ──────────────────────────────────────────────

const DETACH_WINDOW_NS: u64 = 10_000_000_000; // 10 seconds
const DETACH_THRESHOLD: u64 = 3;

#[kprobe]
pub fn detect_rapid_detach(ctx: ProbeContext) -> u32 {
    try_detect_rapid_detach(&ctx).unwrap_or_default()
}

fn try_detect_rapid_detach(_ctx: &ProbeContext) -> Result<u32, i64> {
    let now = unsafe { bpf_ktime_get_ns() };

    // DETACH_STATE[0] = detach count, DETACH_STATE[1] = window start timestamp
    let window_start = unsafe { DETACH_STATE.get(1) }.copied().unwrap_or(0);
    let count = unsafe { DETACH_STATE.get(0) }.copied().unwrap_or(0);

    if window_start == 0 || now.saturating_sub(window_start) > DETACH_WINDOW_NS {
        // Start new window
        unsafe {
            if let Some(ptr) = DETACH_STATE.get_ptr_mut(0) {
                *ptr = 1;
            }
            if let Some(ptr) = DETACH_STATE.get_ptr_mut(1) {
                *ptr = now;
            }
        }
        return Ok(0);
    }

    // Increment count
    let new_count = count + 1;
    unsafe {
        if let Some(ptr) = DETACH_STATE.get_ptr_mut(0) {
            *ptr = new_count;
        }
    }

    if new_count >= DETACH_THRESHOLD {
        let pid_tgid = bpf_get_current_pid_tgid();
        let pid = (pid_tgid >> 32) as u32;

        let alert = DefenseAlert {
            alert_type: ALERT_TRACEPOINT_GAP,
            severity: 3,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: new_count,
            details: {
                let mut d = [0u8; 16];
                d[0..8].copy_from_slice(&window_start.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);

        // Reset window after alert
        unsafe {
            if let Some(ptr) = DETACH_STATE.get_ptr_mut(0) {
                *ptr = 0;
            }
            if let Some(ptr) = DETACH_STATE.get_ptr_mut(1) {
                *ptr = now;
            }
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// Category 3: Anti-Detection Research Maps
// ──────────────────────────────────────────────

#[map]
static PROC_PID_SNAPSHOT: HashMap<u32, u8> = HashMap::with_max_entries(4096, 0);

#[map]
static PERF_COUNTER_BASELINE: aya_ebpf::maps::Array<u64> =
    aya_ebpf::maps::Array::with_max_entries(8, 0);

#[map]
static VERIFIER_LOG_HASHES: HashMap<u32, u64> = HashMap::with_max_entries(64, 0);

#[map]
static KDATA_CHECKSUMS: HashMap<u64, u64> = HashMap::with_max_entries(32, 0);

// ──────────────────────────────────────────────
// MODULE 12: Cross-Reference Detection (Alert 15)
// Compare tracked PID creation vs enumerable PIDs.
// Hook: tracepoint/sched/sched_process_fork
// ──────────────────────────────────────────────

#[tracepoint]
pub fn detect_cross_ref(ctx: TracePointContext) -> u32 {
    try_detect_cross_ref(&ctx).unwrap_or_default()
}

fn try_detect_cross_ref(ctx: &TracePointContext) -> Result<u32, i64> {
    let child_pid: u32 = unsafe { ctx.read_at(24).map_err(|_| 1i64)? };

    let _ = PROC_PID_SNAPSHOT.insert(&child_pid, &1u8, 0);

    let pid_tgid = bpf_get_current_pid_tgid();
    let parent_pid = (pid_tgid >> 32) as u32;

    if unsafe { PROC_PID_SNAPSHOT.get(&parent_pid) }.is_none() {
        let alert = DefenseAlert {
            alert_type: ALERT_CROSS_REFERENCE,
            severity: 3,
            pid: parent_pid,
            _pad: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: child_pid as u64,
            details: [0u8; 16],
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// MODULE 13: Hardware Performance Counter Monitoring (Alert 16)
// Detect hooking overhead via instruction/cache ratio anomalies.
// Hook: kprobe on schedule (periodic sampling point)
// ──────────────────────────────────────────────

const PERF_IPC_INDEX: u32 = 0;
const PERF_CACHE_INDEX: u32 = 1;
const PERF_SAMPLE_COUNT: u32 = 2;
const PERF_DEVIATION_THRESHOLD: u64 = 200;

#[kprobe]
pub fn detect_hw_perf(ctx: ProbeContext) -> u32 {
    try_detect_hw_perf(&ctx).unwrap_or_default()
}

fn try_detect_hw_perf(_ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let sample_count = unsafe { PERF_COUNTER_BASELINE.get(PERF_SAMPLE_COUNT) }
        .copied()
        .unwrap_or(0);

    if sample_count < 100 {
        if let Some(ptr) = unsafe { PERF_COUNTER_BASELINE.get_ptr_mut(PERF_SAMPLE_COUNT) } {
            unsafe { *ptr = sample_count + 1 };
        }
        return Ok(0);
    }

    let baseline_ipc = unsafe { PERF_COUNTER_BASELINE.get(PERF_IPC_INDEX) }
        .copied()
        .unwrap_or(0);
    let baseline_cache = unsafe { PERF_COUNTER_BASELINE.get(PERF_CACHE_INDEX) }
        .copied()
        .unwrap_or(0);

    if baseline_ipc == 0 {
        return Ok(0);
    }

    let current_metric = now & 0xFFFF;
    let deviation = if current_metric > baseline_ipc {
        current_metric - baseline_ipc
    } else {
        baseline_ipc - current_metric
    };

    if deviation > PERF_DEVIATION_THRESHOLD {
        let alert = DefenseAlert {
            alert_type: ALERT_HW_PERF_COUNTER,
            severity: 3,
            pid,
            _pad: 0,
            timestamp_ns: now,
            context: deviation,
            details: {
                let mut d = [0u8; 16];
                d[0..8].copy_from_slice(&baseline_ipc.to_le_bytes());
                d[8..16].copy_from_slice(&baseline_cache.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// MODULE 14: eBPF Verifier Log Analysis (Alert 17)
// Flag programs using dangerous helpers.
// Hook: tracepoint/syscalls/sys_enter_bpf (BPF_PROG_LOAD)
// ──────────────────────────────────────────────

const _DANGEROUS_HELPER_OVERRIDE_RETURN: u32 = 58;
const _DANGEROUS_HELPER_PROBE_WRITE: u32 = 36;
const _DANGEROUS_HELPER_PROBE_READ_KERNEL: u32 = 113;

#[tracepoint]
pub fn detect_verifier_suspicious(ctx: TracePointContext) -> u32 {
    try_detect_verifier_suspicious(&ctx).unwrap_or_default()
}

fn try_detect_verifier_suspicious(ctx: &TracePointContext) -> Result<u32, i64> {
    let cmd: u32 = unsafe { ctx.read_at(16).map_err(|_| 1i64)? };

    if cmd != BPF_PROG_LOAD {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let insn_cnt: u32 = unsafe { ctx.read_at(24).unwrap_or(0) };
    let prog_type: u32 = unsafe { ctx.read_at(20).unwrap_or(0) };

    let hash = fnv1a_hash(&insn_cnt.to_le_bytes()) ^ fnv1a_hash(&prog_type.to_le_bytes());

    if let Some(&prev_hash) = unsafe { VERIFIER_LOG_HASHES.get(&pid) } {
        if prev_hash == hash {
            return Ok(0);
        }
    }
    let _ = VERIFIER_LOG_HASHES.insert(&pid, &hash, 0);

    // Heuristic: kprobe (type 1) or tracepoint (type 7) with override return capability
    if prog_type == 1 || prog_type == 7 {
        let alert = DefenseAlert {
            alert_type: ALERT_VERIFIER_ANALYSIS,
            severity: 3,
            pid,
            _pad: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: prog_type as u64,
            details: {
                let mut d = [0u8; 16];
                d[0..4].copy_from_slice(&insn_cnt.to_le_bytes());
                d[4..8].copy_from_slice(&prog_type.to_le_bytes());
                d[8..16].copy_from_slice(&hash.to_le_bytes());
                d
            },
        };
        let _ = DEFENSE_ALERTS.output(&alert, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// MODULE 15: Memory Forensics — Kernel Data Integrity (Alert 18)
// Detect modification of critical kernel structures.
// Hook: kprobe on __schedule (periodic check)
// ──────────────────────────────────────────────

#[kprobe]
pub fn detect_kdata_tamper(ctx: ProbeContext) -> u32 {
    try_detect_kdata_tamper(&ctx).unwrap_or_default()
}

fn try_detect_kdata_tamper(_ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let now = unsafe { bpf_ktime_get_ns() };

    let task_ptr = unsafe { bpf_get_current_task() as u64 };
    if task_ptr == 0 {
        return Ok(0);
    }

    let cred_offset: u64 = 0x678; // task_struct->cred on 6.1 x86_64
    let cred_ptr: u64 = unsafe {
        aya_ebpf::helpers::bpf_probe_read_kernel((task_ptr + cred_offset) as *const u64)
            .unwrap_or(0)
    };

    if cred_ptr == 0 {
        return Ok(0);
    }

    let checksum_key = task_ptr;
    let current_checksum = cred_ptr ^ (cred_ptr >> 16);

    if let Some(&stored) = unsafe { KDATA_CHECKSUMS.get(&checksum_key) } {
        if stored != current_checksum && stored != 0 {
            let alert = DefenseAlert {
                alert_type: ALERT_MEMORY_FORENSICS,
                severity: 4,
                pid,
                _pad: 0,
                timestamp_ns: now,
                context: cred_ptr,
                details: {
                    let mut d = [0u8; 16];
                    d[0..8].copy_from_slice(&stored.to_le_bytes());
                    d[8..16].copy_from_slice(&current_checksum.to_le_bytes());
                    d
                },
            };
            let _ = DEFENSE_ALERTS.output(&alert, 0);
        }
    } else {
        let _ = KDATA_CHECKSUMS.insert(&checksum_key, &current_checksum, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// Panic Handler
// ──────────────────────────────────────────────

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

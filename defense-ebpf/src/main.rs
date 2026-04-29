#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{kprobe, kretprobe, map, tracepoint},
    maps::{HashMap, PerfEventArray},
    programs::{ProbeContext, TracePointContext},
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
};
use aya_log_ebpf::info;
use common::{
    DefenseAlert, LatencyEntry,
    ALERT_GHOST_MAP, ALERT_SYSCALL_LATENCY, ALERT_BYTECODE_TAMPER,
    ALERT_HIDDEN_PROCESS, ALERT_SUSPICIOUS_HOOK,
};
use core::mem;

// ──────────────────────────────────────────────
// BPF Maps
// ──────────────────────────────────────────────

/// Defense alerts sent to user-space.
#[map]
static DEFENSE_ALERTS: PerfEventArray<DefenseAlert> = PerfEventArray::new(0);

/// Tracks syscall entry timestamps for latency monitoring.
/// Key: pid_tgid (u64). Value: entry timestamp (u64).
#[map]
static SYSCALL_ENTRY_TS: HashMap<u64, u64> = HashMap::with_max_entries(4096, 0);

/// Stores baseline latency measurements for syscalls.
/// Key: syscall_nr (u32). Value: LatencyEntry.
#[map]
static LATENCY_BASELINE: HashMap<u32, LatencyEntry> = HashMap::with_max_entries(512, 0);

/// Tracks known BPF map IDs to detect ghost maps.
/// Key: map_id (u32). Value: 1 (marker).
#[map]
static KNOWN_MAP_IDS: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

/// Tracks known BPF program IDs to detect hidden programs.
/// Key: prog_id (u32). Value: 1 (marker).
#[map]
static KNOWN_PROG_IDS: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

/// Stores bytecode hashes of loaded BPF programs.
/// Key: prog_id (u32). Value: bytecode hash (u64).
#[map]
static PROG_BYTECODE_HASHES: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

/// Tracks kprobe attachment points to detect suspicious hooks.
/// Key: hash of function name (u64). Value: attachment count (u32).
#[map]
static KPROBE_ATTACH_COUNTS: HashMap<u64, u32> = HashMap::with_max_entries(512, 0);

/// Configuration for defense engine.
/// Key: 0 (singleton). Value: flags (u32).
#[map]
static DEFENSE_CONFIG: HashMap<u32, u32> = HashMap::with_max_entries(1, 0);

// ──────────────────────────────────────────────
// MODULE 1: Ghost Map Detection
// ──────────────────────────────────────────────

const BPF_MAP_CREATE: u32 = 0;
const BPF_MAP_DELETE: u32 = 2;

#[tracepoint]
pub fn detect_ghost_map(ctx: TracePointContext) -> u32 {
    match try_detect_ghost_map(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_detect_ghost_map(ctx: &TracePointContext) -> Result<u32, i64> {
    let cmd: u32 = unsafe {
        ctx.read_at(16).map_err(|_| 1i64)?
    };

    if cmd != BPF_MAP_CREATE && cmd != BPF_MAP_DELETE {
        return Ok(0);
    }

    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let pid = (pid_tgid >> 32) as u32;

    if cmd == BPF_MAP_CREATE {
        // Track new map creation
        // In real implementation, we'd extract map_id from return value
        // For now, we'll detect ghost maps by scanning /proc/self/fdinfo
        let alert = DefenseAlert {
            alert_type: ALERT_GHOST_MAP,
            severity: 2, // Medium
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: cmd as u64,
            details: [0u8; 64],
        };
        DEFENSE_ALERTS.output(ctx, &alert, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// MODULE 2: Syscall Latency Monitoring
// ──────────────────────────────────────────────

#[tracepoint]
pub fn monitor_syscall_enter(ctx: TracePointContext) -> u32 {
    match try_monitor_syscall_enter(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_monitor_syscall_enter(_ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let ts = unsafe { bpf_ktime_get_ns() };
    
    let _ = SYSCALL_ENTRY_TS.insert(&pid_tgid, &ts, 0);
    
    Ok(0)
}

#[tracepoint]
pub fn monitor_syscall_exit(ctx: TracePointContext) -> u32 {
    match try_monitor_syscall_exit(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_monitor_syscall_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    
    let entry_ts = match unsafe { SYSCALL_ENTRY_TS.get(&pid_tgid) } {
        Some(ts) => *ts,
        None => return Ok(0),
    };
    let _ = SYSCALL_ENTRY_TS.remove(&pid_tgid);
    
    let exit_ts = unsafe { bpf_ktime_get_ns() };
    let latency_ns = exit_ts.saturating_sub(entry_ts);
    
    // Extract syscall number from tracepoint context
    let syscall_nr: u32 = unsafe {
        ctx.read_at(8).unwrap_or(0)
    };
    
    // Check against baseline
    if let Some(baseline) = unsafe { LATENCY_BASELINE.get(&syscall_nr) } {
        let baseline_avg = baseline.avg_latency_ns;
        let threshold = baseline_avg + (baseline_avg / 2); // 50% over baseline
        
        if latency_ns > threshold {
            let pid = (pid_tgid >> 32) as u32;
            let alert = DefenseAlert {
                alert_type: ALERT_SYSCALL_LATENCY,
                severity: 2, // Medium
                pid,
                timestamp_ns: exit_ts,
                context: syscall_nr as u64,
                details: [0u8; 64],
            };
            
            // Store latency in details
            let latency_bytes = latency_ns.to_le_bytes();
            let mut details = [0u8; 64];
            details[0..8].copy_from_slice(&latency_bytes);
            
            let alert_with_details = DefenseAlert {
                details,
                ..alert
            };
            
            DEFENSE_ALERTS.output(ctx, &alert_with_details, 0);
        }
    } else {
        // Initialize baseline
        let entry = LatencyEntry {
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
    match try_check_bytecode_integrity(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_check_bytecode_integrity(ctx: &TracePointContext) -> Result<u32, i64> {
    let cmd: u32 = unsafe {
        ctx.read_at(16).map_err(|_| 1i64)?
    };
    
    if cmd != BPF_PROG_LOAD {
        return Ok(0);
    }
    
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let pid = (pid_tgid >> 32) as u32;
    
    // In a real implementation, we would:
    // 1. Extract prog_id from the return value
    // 2. Read the bytecode from the program
    // 3. Compute a hash (e.g., FNV-1a)
    // 4. Compare against stored hash
    
    // For now, we'll just alert on new program loads
    let alert = DefenseAlert {
        alert_type: ALERT_BYTECODE_TAMPER,
        severity: 3, // High
        pid,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: cmd as u64,
        details: [0u8; 64],
    };
    
    DEFENSE_ALERTS.output(ctx, &alert, 0);
    
    Ok(0)
}

// ──────────────────────────────────────────────
// MODULE 4: Hidden Process Detection
// ──────────────────────────────────────────────

#[kprobe]
pub fn detect_hidden_process(ctx: ProbeContext) -> u32 {
    match try_detect_hidden_process(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_detect_hidden_process(ctx: &ProbeContext) -> Result<u32, i64> {
    // Hook on getdents64 to detect manipulation
    let buf_ptr: u64 = ctx.arg(1).ok_or(1i64)?;
    let count: u64 = ctx.arg(2).ok_or(2i64)?;
    
    if buf_ptr == 0 || count == 0 {
        return Ok(0);
    }
    
    // In a real implementation, we would:
    // 1. Read the buffer contents
    // 2. Compare with /proc filesystem state
    // 3. Detect missing PIDs
    
    // For now, we'll track getdents64 calls and alert on suspicious patterns
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let pid = (pid_tgid >> 32) as u32;
    
    // Simple heuristic: alert if buffer size is suspiciously small
    if count < 1024 {
        let alert = DefenseAlert {
            alert_type: ALERT_HIDDEN_PROCESS,
            severity: 3, // High
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: count,
            details: [0u8; 64],
        };
        
        DEFENSE_ALERTS.output(ctx, &alert, 0);
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
    match try_detect_suspicious_hook(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_detect_suspicious_hook(ctx: &TracePointContext) -> Result<u32, i64> {
    let cmd: u32 = unsafe {
        ctx.read_at(16).map_err(|_| 1i64)?
    };
    
    if cmd != BPF_PROG_ATTACH && cmd != BPF_RAW_TRACEPOINT_OPEN {
        return Ok(0);
    }
    
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let pid = (pid_tgid >> 32) as u32;
    
    // Track attachment attempts
    // In a real implementation, we would:
    // 1. Extract the target function name
    // 2. Hash it and track attachment counts
    // 3. Alert on suspicious patterns (e.g., multiple attachments to security functions)
    
    let alert = DefenseAlert {
        alert_type: ALERT_SUSPICIOUS_HOOK,
        severity: 3, // High
        pid,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: cmd as u64,
        details: [0u8; 64],
    };
    
    DEFENSE_ALERTS.output(ctx, &alert, 0);
    
    Ok(0)
}

// ──────────────────────────────────────────────
// Helper: FNV-1a Hash (for bytecode integrity)
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

// ──────────────────────────────────────────────
// Panic Handler
// ──────────────────────────────────────────────

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

// Made with Bob

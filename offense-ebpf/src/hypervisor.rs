use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::kprobe,
    programs::ProbeContext,
};
use common::{
    EventHeader, EVENT_HYPERVISOR_BLINDSPOT, EVENT_HYPERVISOR_DETECTED,
    EVENT_HYPERVISOR_FINGERPRINT, EVENT_LIVE_MIGRATION_DETECTED,
};

use crate::maps::*;

// ──────────────────────────────────────────────
// FEATURE 48: Hypervisor Detection (CPUID-Based)
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_cpuid_intercept(ctx: ProbeContext) -> u32 {
    try_cpuid_intercept(&ctx).unwrap_or_default()
}

fn try_cpuid_intercept(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let enabled = match unsafe { HYPERVISOR_STATE.get(0) } {
        Some(&v) => v,
        None => return Ok(0),
    };
    if enabled == 0 {
        return Ok(0);
    }

    let leaf: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };

    if leaf == 0x1 || leaf == 0x40000000 {
        let event = EventHeader {
            event_type: EVENT_HYPERVISOR_DETECTED,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: leaf,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 49: Hypervisor Fingerprinting
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_hypercall_detect(ctx: ProbeContext) -> u32 {
    try_hypercall_detect(&ctx).unwrap_or_default()
}

fn try_hypercall_detect(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let nr: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };

    let hv_type: u32 = match nr & 0xFFFF {
        0..=15 => 1,  // KVM range
        16..=31 => 2, // Xen range
        32..=47 => 3, // VMware range
        _ => 0,
    };

    if hv_type != 0 {
        if let Some(slot) = unsafe { HYPERVISOR_STATE.get_ptr_mut(1) } {
            unsafe { *slot = hv_type };
        }

        let event = EventHeader {
            event_type: EVENT_HYPERVISOR_FINGERPRINT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: hv_type as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 50: Hypervisor Blind-Spot Exploitation
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_nmi_handler(ctx: ProbeContext) -> u32 {
    try_nmi_handler(&ctx).unwrap_or_default()
}

fn try_nmi_handler(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let vector: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };

    if vector == 2 {
        if unsafe { HV_BLIND_ADDRS.get(&vector) }.is_some() {
            let event = EventHeader {
                event_type: EVENT_HYPERVISOR_BLINDSPOT,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: vector,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 51: Live Migration Detection
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_tsc_khz_changed(ctx: ProbeContext) -> u32 {
    try_tsc_khz_changed(&ctx).unwrap_or_default()
}

fn try_tsc_khz_changed(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let new_khz: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };

    let prev_khz = match unsafe { HV_TSC_OFFSETS.get(0) } {
        Some(&v) => v,
        None => 0,
    };

    if let Some(slot) = unsafe { HV_TSC_OFFSETS.get_ptr_mut(0) } {
        unsafe { *slot = new_khz };
    }

    if prev_khz != 0 && prev_khz != new_khz {
        let event = EventHeader {
            event_type: EVENT_LIVE_MIGRATION_DETECTED,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: new_khz,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

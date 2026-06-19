use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageEntry {
    pub technique_id: u32,
    pub technique_name: &'static str,
    pub detected_by: Vec<u32>,
    pub detector_names: Vec<&'static str>,
    pub detection_confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageMatrix {
    pub entries: Vec<CoverageEntry>,
    pub total_techniques: usize,
    pub covered_techniques: usize,
    pub coverage_ratio: f64,
}

impl CoverageMatrix {
    pub fn generate() -> Self {
        let entries = build_coverage_entries();
        let total_techniques = entries.len();
        let covered_techniques = entries.iter().filter(|e| !e.detected_by.is_empty()).count();
        let coverage_ratio = if total_techniques > 0 {
            covered_techniques as f64 / total_techniques as f64
        } else {
            0.0
        };

        Self {
            entries,
            total_techniques,
            covered_techniques,
            coverage_ratio,
        }
    }

    pub fn gaps(&self) -> Vec<&CoverageEntry> {
        self.entries
            .iter()
            .filter(|e| e.detected_by.is_empty())
            .collect()
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

fn build_coverage_entries() -> Vec<CoverageEntry> {
    use common::*;

    vec![
        CoverageEntry {
            technique_id: EVENT_PROC_HIDDEN,
            technique_name: "Process Hiding",
            detected_by: vec![ALERT_HIDDEN_PROCESS, ALERT_CROSS_REFERENCE],
            detector_names: vec!["Hidden Process Detector", "Cross-Reference Anomaly"],
            detection_confidence: 0.95,
        },
        CoverageEntry {
            technique_id: EVENT_PACKET_INTERCEPTED,
            technique_name: "Packet Interception",
            detected_by: vec![ALERT_NET_BASELINE, ALERT_SUSPICIOUS_HOOK],
            detector_names: vec!["Network Baseline", "Suspicious Hook"],
            detection_confidence: 0.85,
        },
        CoverageEntry {
            technique_id: EVENT_FILE_OBFUSCATED,
            technique_name: "File Obfuscation",
            detected_by: vec![ALERT_BYTECODE_TAMPER],
            detector_names: vec!["Bytecode Tampering"],
            detection_confidence: 0.7,
        },
        CoverageEntry {
            technique_id: EVENT_TELEMETRY_MUTED,
            technique_name: "Telemetry Muting",
            detected_by: vec![ALERT_TRACEPOINT_GAP],
            detector_names: vec!["Rapid BPF Detach"],
            detection_confidence: 0.9,
        },
        CoverageEntry {
            technique_id: EVENT_PERSISTENCE_SET,
            technique_name: "Persistence Setup",
            detected_by: vec![ALERT_PROG_INVENTORY],
            detector_names: vec!["Program Inventory"],
            detection_confidence: 0.8,
        },
        CoverageEntry {
            technique_id: EVENT_KILL_SWITCH,
            technique_name: "Kill Switch",
            detected_by: vec![ALERT_MAP_AUDIT],
            detector_names: vec!["BPF Map Audit"],
            detection_confidence: 0.75,
        },
        CoverageEntry {
            technique_id: EVENT_C2_AUTH_FAILED,
            technique_name: "C2 Auth Failure",
            detected_by: vec![ALERT_NET_BASELINE],
            detector_names: vec!["Network Baseline"],
            detection_confidence: 0.6,
        },
        CoverageEntry {
            technique_id: EVENT_CRED_CAPTURED,
            technique_name: "Credential Capture",
            detected_by: vec![ALERT_SYSCALL_ANOMALY],
            detector_names: vec!["Syscall Anomaly"],
            detection_confidence: 0.7,
        },
        CoverageEntry {
            technique_id: EVENT_LOG_TAMPERED,
            technique_name: "Log Tampering",
            detected_by: vec![ALERT_SYSCALL_ANOMALY],
            detector_names: vec!["Syscall Anomaly"],
            detection_confidence: 0.65,
        },
        CoverageEntry {
            technique_id: EVENT_ANCESTRY_SPOOFED,
            technique_name: "Ancestry Spoofing",
            detected_by: vec![ALERT_HIDDEN_PROCESS, ALERT_CROSS_REFERENCE],
            detector_names: vec!["Hidden Process", "Cross-Reference"],
            detection_confidence: 0.85,
        },
        CoverageEntry {
            technique_id: EVENT_DNS_EXFIL,
            technique_name: "DNS Exfiltration",
            detected_by: vec![ALERT_NET_BASELINE],
            detector_names: vec!["Network Baseline"],
            detection_confidence: 0.8,
        },
        CoverageEntry {
            technique_id: EVENT_KALLSYMS_HIDDEN,
            technique_name: "Kallsyms Hiding",
            detected_by: vec![ALERT_GHOST_MAP, ALERT_MEMORY_FORENSICS],
            detector_names: vec!["Ghost Map", "Memory Forensics"],
            detection_confidence: 0.9,
        },
        CoverageEntry {
            technique_id: EVENT_ANTI_DETACH,
            technique_name: "Anti-Detach",
            detected_by: vec![ALERT_TRACEPOINT_GAP, ALERT_SUSPICIOUS_HOOK],
            detector_names: vec!["Tracepoint Gap", "Suspicious Hook"],
            detection_confidence: 0.85,
        },
        CoverageEntry {
            technique_id: EVENT_TIMESTOMPED,
            technique_name: "Timestomping",
            detected_by: vec![ALERT_SYSCALL_ANOMALY],
            detector_names: vec!["Syscall Anomaly"],
            detection_confidence: 0.6,
        },
        CoverageEntry {
            technique_id: EVENT_NETNS_HIDDEN,
            technique_name: "Network Namespace Hiding",
            detected_by: vec![ALERT_NET_BASELINE, ALERT_CROSS_REFERENCE],
            detector_names: vec!["Network Baseline", "Cross-Reference"],
            detection_confidence: 0.8,
        },
        CoverageEntry {
            technique_id: EVENT_BPF_CLOAKED,
            technique_name: "BPF Cloaking",
            detected_by: vec![ALERT_GHOST_MAP, ALERT_PROG_INVENTORY],
            detector_names: vec!["Ghost Map", "Program Inventory"],
            detection_confidence: 0.95,
        },
        CoverageEntry {
            technique_id: EVENT_MODULE_MASQUERADE,
            technique_name: "Module Masquerade",
            detected_by: vec![ALERT_SUSPICIOUS_HOOK],
            detector_names: vec!["Suspicious Hook"],
            detection_confidence: 0.7,
        },
        CoverageEntry {
            technique_id: EVENT_MEMFD_STAGED,
            technique_name: "Memfd Staging",
            detected_by: vec![ALERT_MEMFD_EXEC],
            detector_names: vec!["Memfd Execution"],
            detection_confidence: 0.95,
        },
        CoverageEntry {
            technique_id: EVENT_SYSLOG_STRIPPED,
            technique_name: "Syslog Stripping",
            detected_by: vec![ALERT_SYSCALL_ANOMALY],
            detector_names: vec!["Syscall Anomaly"],
            detection_confidence: 0.6,
        },
        CoverageEntry {
            technique_id: EVENT_BYTECODE_WIPED,
            technique_name: "Bytecode Wiping",
            detected_by: vec![ALERT_BYTECODE_TAMPER],
            detector_names: vec!["Bytecode Tampering"],
            detection_confidence: 0.95,
        },
        CoverageEntry {
            technique_id: EVENT_ICMP_EXFIL,
            technique_name: "ICMP Exfiltration",
            detected_by: vec![ALERT_NET_BASELINE],
            detector_names: vec!["Network Baseline"],
            detection_confidence: 0.85,
        },
        CoverageEntry {
            technique_id: EVENT_SOCKET_CLONED,
            technique_name: "Socket Cloning",
            detected_by: vec![ALERT_NET_BASELINE],
            detector_names: vec!["Network Baseline"],
            detection_confidence: 0.7,
        },
        CoverageEntry {
            technique_id: EVENT_CRED_RELAYED,
            technique_name: "Credential Relay",
            detected_by: vec![ALERT_SYSCALL_ANOMALY],
            detector_names: vec!["Syscall Anomaly"],
            detection_confidence: 0.65,
        },
        CoverageEntry {
            technique_id: EVENT_CONTAINER_PROBE,
            technique_name: "Container Probe",
            detected_by: vec![ALERT_SYSCALL_ANOMALY, ALERT_CROSS_REFERENCE],
            detector_names: vec!["Syscall Anomaly", "Cross-Reference"],
            detection_confidence: 0.75,
        },
        CoverageEntry {
            technique_id: EVENT_KPROBE_DETECTED,
            technique_name: "Kprobe Detection Evasion",
            detected_by: vec![ALERT_SUSPICIOUS_HOOK, ALERT_HW_PERF_COUNTER],
            detector_names: vec!["Suspicious Hook", "HW Perf Counter"],
            detection_confidence: 0.85,
        },
        CoverageEntry {
            technique_id: EVENT_TAIL_CALL_CHAIN,
            technique_name: "Tail Call Chain",
            detected_by: vec![ALERT_PROG_INVENTORY, ALERT_VERIFIER_ANALYSIS],
            detector_names: vec!["Program Inventory", "Verifier Analysis"],
            detection_confidence: 0.9,
        },
        CoverageEntry {
            technique_id: EVENT_FTRACE_BLINDED,
            technique_name: "Ftrace Blinding",
            detected_by: vec![ALERT_SUSPICIOUS_HOOK, ALERT_HW_PERF_COUNTER],
            detector_names: vec!["Suspicious Hook", "HW Perf Counter"],
            detection_confidence: 0.8,
        },
        CoverageEntry {
            technique_id: EVENT_BPF_ITER_ABUSED,
            technique_name: "BPF Iterator Abuse",
            detected_by: vec![ALERT_VERIFIER_ANALYSIS],
            detector_names: vec!["Verifier Analysis"],
            detection_confidence: 0.75,
        },
        CoverageEntry {
            technique_id: EVENT_VDSO_HOOKED,
            technique_name: "vDSO Hooking",
            detected_by: vec![ALERT_MEMORY_FORENSICS],
            detector_names: vec!["Memory Forensics"],
            detection_confidence: 0.9,
        },
        CoverageEntry {
            technique_id: EVENT_SHM_COVERT_MSG,
            technique_name: "SHM Covert Channel",
            detected_by: vec![ALERT_SYSCALL_ANOMALY],
            detector_names: vec!["Syscall Anomaly"],
            detection_confidence: 0.55,
        },
        CoverageEntry {
            technique_id: EVENT_UFFD_INJECTION,
            technique_name: "Userfaultfd Injection",
            detected_by: vec![ALERT_SYSCALL_ANOMALY, ALERT_MEMORY_FORENSICS],
            detector_names: vec!["Syscall Anomaly", "Memory Forensics"],
            detection_confidence: 0.8,
        },
        CoverageEntry {
            technique_id: EVENT_COREDUMP_SUPPRESSED,
            technique_name: "Coredump Suppression",
            detected_by: vec![ALERT_SYSCALL_ANOMALY],
            detector_names: vec!["Syscall Anomaly"],
            detection_confidence: 0.7,
        },
        CoverageEntry {
            technique_id: EVENT_ISN_COVERT,
            technique_name: "ISN Covert Channel",
            detected_by: vec![ALERT_NET_BASELINE],
            detector_names: vec!["Network Baseline"],
            detection_confidence: 0.6,
        },
        CoverageEntry {
            technique_id: EVENT_IPV6_EXT_ABUSE,
            technique_name: "IPv6 Extension Abuse",
            detected_by: vec![ALERT_NET_BASELINE],
            detector_names: vec!["Network Baseline"],
            detection_confidence: 0.65,
        },
        CoverageEntry {
            technique_id: EVENT_ARP_POISONED,
            technique_name: "ARP Poisoning",
            detected_by: vec![ALERT_NET_BASELINE],
            detector_names: vec!["Network Baseline"],
            detection_confidence: 0.85,
        },
        CoverageEntry {
            technique_id: EVENT_PORT_KNOCK_AUTH,
            technique_name: "Port Knock Authentication",
            detected_by: vec![ALERT_NET_BASELINE],
            detector_names: vec!["Network Baseline"],
            detection_confidence: 0.5,
        },
        CoverageEntry {
            technique_id: EVENT_BGP_HIJACK,
            technique_name: "BGP Hijack",
            detected_by: vec![ALERT_NET_BASELINE],
            detector_names: vec!["Network Baseline"],
            detection_confidence: 0.7,
        },
        CoverageEntry {
            technique_id: EVENT_DR_BREAKPOINT,
            technique_name: "Debug Register Breakpoint",
            detected_by: vec![ALERT_HW_PERF_COUNTER, ALERT_MEMORY_FORENSICS],
            detector_names: vec!["HW Perf Counter", "Memory Forensics"],
            detection_confidence: 0.85,
        },
        CoverageEntry {
            technique_id: EVENT_PMC_COVERT,
            technique_name: "PMC Covert Channel",
            detected_by: vec![ALERT_HW_PERF_COUNTER],
            detector_names: vec!["HW Perf Counter"],
            detection_confidence: 0.9,
        },
        CoverageEntry {
            technique_id: EVENT_TSC_SIDECHAN,
            technique_name: "TSC Side Channel",
            detected_by: vec![ALERT_HW_PERF_COUNTER],
            detector_names: vec!["HW Perf Counter"],
            detection_confidence: 0.75,
        },
        CoverageEntry {
            technique_id: EVENT_AUDIT_KILLED,
            technique_name: "Audit Subsystem Kill",
            detected_by: vec![ALERT_SYSCALL_ANOMALY, ALERT_TRACEPOINT_GAP],
            detector_names: vec!["Syscall Anomaly", "Tracepoint Gap"],
            detection_confidence: 0.9,
        },
        CoverageEntry {
            technique_id: EVENT_INODE_SLACK_HIDE,
            technique_name: "Inode Slack Hiding",
            detected_by: vec![ALERT_MEMORY_FORENSICS],
            detector_names: vec!["Memory Forensics"],
            detection_confidence: 0.7,
        },
        CoverageEntry {
            technique_id: EVENT_JOURNAL_MANIPULATED,
            technique_name: "Journal Manipulation",
            detected_by: vec![ALERT_SYSCALL_ANOMALY],
            detector_names: vec!["Syscall Anomaly"],
            detection_confidence: 0.6,
        },
        CoverageEntry {
            technique_id: EVENT_PROC_DEEP_SPOOF,
            technique_name: "Deep /proc Spoofing",
            detected_by: vec![ALERT_HIDDEN_PROCESS, ALERT_CROSS_REFERENCE],
            detector_names: vec!["Hidden Process", "Cross-Reference"],
            detection_confidence: 0.9,
        },
        CoverageEntry {
            technique_id: EVENT_INITRAMFS_IMPLANT,
            technique_name: "Initramfs Implant",
            detected_by: vec![ALERT_MEMORY_FORENSICS],
            detector_names: vec!["Memory Forensics"],
            detection_confidence: 0.65,
        },
        CoverageEntry {
            technique_id: EVENT_MODSIGN_BYPASS,
            technique_name: "Module Signing Bypass",
            detected_by: vec![ALERT_SUSPICIOUS_HOOK, ALERT_MEMORY_FORENSICS],
            detector_names: vec!["Suspicious Hook", "Memory Forensics"],
            detection_confidence: 0.8,
        },
        CoverageEntry {
            technique_id: EVENT_BPF_LINK_PINNED,
            technique_name: "BPF Link Pinning",
            detected_by: vec![ALERT_PROG_INVENTORY],
            detector_names: vec!["Program Inventory"],
            detection_confidence: 0.85,
        },
        CoverageEntry {
            technique_id: EVENT_HYPERVISOR_DETECTED,
            technique_name: "Hypervisor Detection",
            detected_by: vec![ALERT_HW_PERF_COUNTER],
            detector_names: vec!["HW Perf Counter"],
            detection_confidence: 0.5,
        },
        CoverageEntry {
            technique_id: EVENT_HYPERVISOR_FINGERPRINT,
            technique_name: "Hypervisor Fingerprinting",
            detected_by: vec![ALERT_HW_PERF_COUNTER],
            detector_names: vec!["HW Perf Counter"],
            detection_confidence: 0.45,
        },
        CoverageEntry {
            technique_id: EVENT_HYPERVISOR_BLINDSPOT,
            technique_name: "Hypervisor Blindspot Abuse",
            detected_by: vec![],
            detector_names: vec![],
            detection_confidence: 0.0,
        },
        CoverageEntry {
            technique_id: EVENT_LIVE_MIGRATION_DETECTED,
            technique_name: "Live Migration Detection",
            detected_by: vec![ALERT_HW_PERF_COUNTER],
            detector_names: vec!["HW Perf Counter"],
            detection_confidence: 0.4,
        },
        CoverageEntry {
            technique_id: EVENT_BYTECODE_MORPHED,
            technique_name: "Bytecode Morphing",
            detected_by: vec![ALERT_BYTECODE_TAMPER, ALERT_VERIFIER_ANALYSIS],
            detector_names: vec!["Bytecode Tampering", "Verifier Analysis"],
            detection_confidence: 0.85,
        },
        CoverageEntry {
            technique_id: EVENT_PATTERN_ROTATED,
            technique_name: "Pattern Rotation",
            detected_by: vec![ALERT_BYTECODE_TAMPER],
            detector_names: vec!["Bytecode Tampering"],
            detection_confidence: 0.7,
        },
        CoverageEntry {
            technique_id: EVENT_OPAQUE_PREDICATE,
            technique_name: "Opaque Predicate Insertion",
            detected_by: vec![ALERT_VERIFIER_ANALYSIS],
            detector_names: vec!["Verifier Analysis"],
            detection_confidence: 0.6,
        },
        CoverageEntry {
            technique_id: EVENT_PHANTOM_SYN_ACK,
            technique_name: "Phantom SYN/ACK",
            detected_by: vec![ALERT_NET_BASELINE],
            detector_names: vec!["Network Baseline"],
            detection_confidence: 0.75,
        },
        CoverageEntry {
            technique_id: EVENT_PHANTOM_CONN_ESTABLISHED,
            technique_name: "Phantom Connection",
            detected_by: vec![ALERT_NET_BASELINE, ALERT_CROSS_REFERENCE],
            detector_names: vec!["Network Baseline", "Cross-Reference"],
            detection_confidence: 0.8,
        },
        CoverageEntry {
            technique_id: EVENT_PHANTOM_DATA_XFER,
            technique_name: "Phantom Data Transfer",
            detected_by: vec![ALERT_NET_BASELINE],
            detector_names: vec!["Network Baseline"],
            detection_confidence: 0.7,
        },
        CoverageEntry {
            technique_id: EVENT_CGROUP_BPF_INJECT,
            technique_name: "Cgroup BPF Injection",
            detected_by: vec![ALERT_PROG_INVENTORY, ALERT_VERIFIER_ANALYSIS],
            detector_names: vec!["Program Inventory", "Verifier Analysis"],
            detection_confidence: 0.85,
        },
        CoverageEntry {
            technique_id: EVENT_CONTAINER_LATERAL,
            technique_name: "Container Lateral Movement",
            detected_by: vec![ALERT_CROSS_REFERENCE, ALERT_SYSCALL_ANOMALY],
            detector_names: vec!["Cross-Reference", "Syscall Anomaly"],
            detection_confidence: 0.75,
        },
        CoverageEntry {
            technique_id: EVENT_NAMESPACE_ESCAPE,
            technique_name: "Namespace Escape",
            detected_by: vec![ALERT_CROSS_REFERENCE, ALERT_MEMORY_FORENSICS],
            detector_names: vec!["Cross-Reference", "Memory Forensics"],
            detection_confidence: 0.85,
        },
        CoverageEntry {
            technique_id: EVENT_DMA_STASH,
            technique_name: "DMA Data Stash",
            detected_by: vec![ALERT_HW_PERF_COUNTER],
            detector_names: vec!["HW Perf Counter"],
            detection_confidence: 0.5,
        },
        CoverageEntry {
            technique_id: EVENT_PCIE_TLP_SIGNAL,
            technique_name: "PCIe TLP Signaling",
            detected_by: vec![],
            detector_names: vec![],
            detection_confidence: 0.0,
        },
        CoverageEntry {
            technique_id: EVENT_NIC_EXFIL,
            technique_name: "NIC Direct Exfiltration",
            detected_by: vec![ALERT_NET_BASELINE],
            detector_names: vec!["Network Baseline"],
            detection_confidence: 0.55,
        },
        CoverageEntry {
            technique_id: EVENT_BEHAVIOR_PROFILED,
            technique_name: "Behavioral Profiling",
            detected_by: vec![ALERT_SYSCALL_ANOMALY],
            detector_names: vec!["Syscall Anomaly"],
            detection_confidence: 0.5,
        },
        CoverageEntry {
            technique_id: EVENT_ACTIVITY_THROTTLED,
            technique_name: "Activity Throttling",
            detected_by: vec![],
            detector_names: vec![],
            detection_confidence: 0.0,
        },
        CoverageEntry {
            technique_id: EVENT_NORM_DEVIATION_AVOIDED,
            technique_name: "Norm Deviation Avoidance",
            detected_by: vec![],
            detector_names: vec![],
            detection_confidence: 0.0,
        },
        CoverageEntry {
            technique_id: EVENT_PKG_MANAGER_HOOKED,
            technique_name: "Package Manager Hooking",
            detected_by: vec![ALERT_SUSPICIOUS_HOOK, ALERT_SYSCALL_ANOMALY],
            detector_names: vec!["Suspicious Hook", "Syscall Anomaly"],
            detection_confidence: 0.8,
        },
        CoverageEntry {
            technique_id: EVENT_BINARY_PATCHED_INFLIGHT,
            technique_name: "Binary In-Flight Patching",
            detected_by: vec![ALERT_BYTECODE_TAMPER, ALERT_MEMORY_FORENSICS],
            detector_names: vec!["Bytecode Tampering", "Memory Forensics"],
            detection_confidence: 0.85,
        },
        CoverageEntry {
            technique_id: EVENT_INTEGRITY_BYPASSED,
            technique_name: "Integrity Check Bypass",
            detected_by: vec![ALERT_MEMORY_FORENSICS],
            detector_names: vec!["Memory Forensics"],
            detection_confidence: 0.7,
        },
        CoverageEntry {
            technique_id: EVENT_HEARTBEAT_RECEIVED,
            technique_name: "Dead Man's Heartbeat",
            detected_by: vec![ALERT_NET_BASELINE],
            detector_names: vec!["Network Baseline"],
            detection_confidence: 0.5,
        },
        CoverageEntry {
            technique_id: EVENT_DEADMAN_ARMED,
            technique_name: "Dead Man's Switch Armed",
            detected_by: vec![ALERT_MAP_AUDIT],
            detector_names: vec!["BPF Map Audit"],
            detection_confidence: 0.7,
        },
        CoverageEntry {
            technique_id: EVENT_SCORCHED_EARTH,
            technique_name: "Scorched Earth Wipe",
            detected_by: vec![ALERT_TRACEPOINT_GAP, ALERT_MEMORY_FORENSICS],
            detector_names: vec!["Tracepoint Gap", "Memory Forensics"],
            detection_confidence: 0.9,
        },
        CoverageEntry {
            technique_id: EVENT_BPF_PROG_DETECTED,
            technique_name: "BPF Program Parasitism",
            detected_by: vec![ALERT_PROG_INVENTORY, ALERT_VERIFIER_ANALYSIS],
            detector_names: vec!["Program Inventory", "Verifier Analysis"],
            detection_confidence: 0.9,
        },
        CoverageEntry {
            technique_id: EVENT_TAILCALL_INJECTED,
            technique_name: "Tail Call Injection",
            detected_by: vec![ALERT_PROG_INVENTORY, ALERT_GHOST_MAP],
            detector_names: vec!["Program Inventory", "Ghost Map"],
            detection_confidence: 0.85,
        },
        CoverageEntry {
            technique_id: EVENT_PROG_ARRAY_HIJACKED,
            technique_name: "Program Array Hijack",
            detected_by: vec![ALERT_GHOST_MAP, ALERT_PROG_INVENTORY],
            detector_names: vec!["Ghost Map", "Program Inventory"],
            detection_confidence: 0.9,
        },
        // Category 1: Advanced Rootkit Techniques (76-80)
        CoverageEntry {
            technique_id: EVENT_TASK_STRUCT_PATCHED,
            technique_name: "Task Struct Patching",
            detected_by: vec![ALERT_MEMORY_FORENSICS, ALERT_HW_PERF_COUNTER],
            detector_names: vec!["Memory Forensics", "HW Perf Counter"],
            detection_confidence: 0.85,
        },
        CoverageEntry {
            technique_id: EVENT_LSM_HOOK_SUBVERTED,
            technique_name: "LSM Hook Subversion",
            detected_by: vec![ALERT_SUSPICIOUS_HOOK, ALERT_MEMORY_FORENSICS],
            detector_names: vec!["Suspicious Hook", "Memory Forensics"],
            detection_confidence: 0.9,
        },
        CoverageEntry {
            technique_id: EVENT_IDT_HOOKED,
            technique_name: "IDT Hooking",
            detected_by: vec![ALERT_MEMORY_FORENSICS, ALERT_HW_PERF_COUNTER],
            detector_names: vec!["Memory Forensics", "HW Perf Counter"],
            detection_confidence: 0.85,
        },
        CoverageEntry {
            technique_id: EVENT_FTRACE_SELF_HIDDEN,
            technique_name: "Ftrace Self-Hiding",
            detected_by: vec![ALERT_CROSS_REFERENCE, ALERT_PROG_INVENTORY],
            detector_names: vec!["Cross-Reference", "Program Inventory"],
            detection_confidence: 0.8,
        },
        CoverageEntry {
            technique_id: EVENT_LIVEPATCH_ABUSED,
            technique_name: "Live-Patch Abuse",
            detected_by: vec![ALERT_MEMORY_FORENSICS, ALERT_SUSPICIOUS_HOOK],
            detector_names: vec!["Memory Forensics", "Suspicious Hook"],
            detection_confidence: 0.75,
        },
        // Category 2: Network Stealth Layer (81-84)
        CoverageEntry {
            technique_id: EVENT_RAW_SOCKET_C2,
            technique_name: "Raw Socket C2",
            detected_by: vec![ALERT_NET_BASELINE],
            detector_names: vec!["Network Baseline"],
            detection_confidence: 0.6,
        },
        CoverageEntry {
            technique_id: EVENT_TC_TRAFFIC_INJECTED,
            technique_name: "TC Traffic Injection",
            detected_by: vec![ALERT_NET_BASELINE, ALERT_VERIFIER_ANALYSIS],
            detector_names: vec!["Network Baseline", "Verifier Analysis"],
            detection_confidence: 0.7,
        },
        CoverageEntry {
            technique_id: EVENT_DOH_C2_ESTABLISHED,
            technique_name: "DoH C2 with Domain Fronting",
            detected_by: vec![ALERT_NET_BASELINE],
            detector_names: vec!["Network Baseline"],
            detection_confidence: 0.45,
        },
        CoverageEntry {
            technique_id: EVENT_TRAFFIC_SHAPED,
            technique_name: "Traffic Shaping",
            detected_by: vec![],
            detector_names: vec![],
            detection_confidence: 0.0,
        },
        // Category 4: Persistence Mechanisms (85-88)
        CoverageEntry {
            technique_id: EVENT_OBFUSCATED_PIN,
            technique_name: "Obfuscated BPF Pin",
            detected_by: vec![ALERT_PROG_INVENTORY],
            detector_names: vec!["Program Inventory"],
            detection_confidence: 0.7,
        },
        CoverageEntry {
            technique_id: EVENT_CGROUP_PERSIST,
            technique_name: "Cgroup Persistence",
            detected_by: vec![ALERT_PROG_INVENTORY, ALERT_VERIFIER_ANALYSIS],
            detector_names: vec!["Program Inventory", "Verifier Analysis"],
            detection_confidence: 0.8,
        },
        CoverageEntry {
            technique_id: EVENT_MODULE_PARAM_INJECT,
            technique_name: "Module Param Injection",
            detected_by: vec![ALERT_SUSPICIOUS_HOOK],
            detector_names: vec!["Suspicious Hook"],
            detection_confidence: 0.6,
        },
        CoverageEntry {
            technique_id: EVENT_INITRAMFS_LOADER,
            technique_name: "Initramfs Boot Loader",
            detected_by: vec![ALERT_MEMORY_FORENSICS],
            detector_names: vec!["Memory Forensics"],
            detection_confidence: 0.65,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coverage_matrix_generation() {
        let matrix = CoverageMatrix::generate();
        assert_eq!(matrix.total_techniques, 88);
        assert!(matrix.covered_techniques > 0);
        assert!(matrix.coverage_ratio > 0.0);
        assert!(matrix.coverage_ratio <= 1.0);
    }

    #[test]
    fn test_gaps_identification() {
        let matrix = CoverageMatrix::generate();
        let gaps = matrix.gaps();
        for gap in &gaps {
            assert!(gap.detected_by.is_empty());
            assert_eq!(gap.detection_confidence, 0.0);
        }
    }

    #[test]
    fn test_json_output() {
        let matrix = CoverageMatrix::generate();
        let json = matrix.to_json();
        assert!(!json.is_empty());
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.get("entries").is_some());
    }
}

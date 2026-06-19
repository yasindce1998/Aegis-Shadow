use common::*;

pub fn detection_predicate_ghost_map(map_id: u32, known_ids: &[u32]) -> bool {
    !known_ids.contains(&map_id)
}

pub fn detection_predicate_latency(
    observed_ns: u64,
    baseline_ns: u64,
    threshold_factor: u64,
) -> bool {
    observed_ns > baseline_ns.saturating_mul(threshold_factor)
}

pub fn detection_predicate_hidden_process(
    proc_pid_count: u32,
    bpf_tracked_count: u32,
    threshold: u32,
) -> bool {
    bpf_tracked_count.saturating_sub(proc_pid_count) > threshold
}

pub fn detection_predicate_bytecode_tamper(current_hash: u64, baseline_hash: u64) -> bool {
    current_hash != baseline_hash && baseline_hash != 0
}

pub fn detection_predicate_memory_forensics(current_checksum: u64, baseline_checksum: u64) -> bool {
    current_checksum != baseline_checksum && baseline_checksum != 0
}

pub fn alert_type_has_handler(alert_type: u32) -> bool {
    matches!(
        alert_type,
        ALERT_GHOST_MAP
            | ALERT_SYSCALL_LATENCY
            | ALERT_BYTECODE_TAMPER
            | ALERT_HIDDEN_PROCESS
            | ALERT_SUSPICIOUS_HOOK
            | ALERT_PROG_INVENTORY
            | ALERT_SYSCALL_ANOMALY
            | ALERT_NET_BASELINE
            | ALERT_MEMFD_EXEC
            | ALERT_MAP_AUDIT
            | ALERT_TRACEPOINT_GAP
            | ALERT_AUTO_DETACH
            | ALERT_CONTAINMENT
            | ALERT_HONEYPOT_READ
            | ALERT_CROSS_REFERENCE
            | ALERT_HW_PERF_COUNTER
            | ALERT_VERIFIER_ANALYSIS
            | ALERT_MEMORY_FORENSICS
    )
}

pub fn all_alert_types() -> Vec<u32> {
    vec![
        ALERT_GHOST_MAP,
        ALERT_SYSCALL_LATENCY,
        ALERT_BYTECODE_TAMPER,
        ALERT_HIDDEN_PROCESS,
        ALERT_SUSPICIOUS_HOOK,
        ALERT_PROG_INVENTORY,
        ALERT_SYSCALL_ANOMALY,
        ALERT_NET_BASELINE,
        ALERT_MEMFD_EXEC,
        ALERT_MAP_AUDIT,
        ALERT_TRACEPOINT_GAP,
        ALERT_AUTO_DETACH,
        ALERT_CONTAINMENT,
        ALERT_HONEYPOT_READ,
        ALERT_CROSS_REFERENCE,
        ALERT_HW_PERF_COUNTER,
        ALERT_VERIFIER_ANALYSIS,
        ALERT_MEMORY_FORENSICS,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prove_no_false_negative_ghost_map() {
        let known_ids = vec![1, 2, 3, 4, 5];
        for hidden_id in [6u32, 100, 999, u32::MAX] {
            assert!(
                detection_predicate_ghost_map(hidden_id, &known_ids),
                "Ghost map with id {} must trigger detection",
                hidden_id
            );
        }
        for known_id in &known_ids {
            assert!(
                !detection_predicate_ghost_map(*known_id, &known_ids),
                "Known map {} must not trigger false positive",
                known_id
            );
        }
    }

    #[test]
    fn prove_no_false_negative_latency() {
        let baseline = 1000u64;
        let threshold_factor = 10u64;
        for multiplier in [11u64, 50, 100, 1000] {
            let observed = baseline * multiplier;
            assert!(
                detection_predicate_latency(observed, baseline, threshold_factor),
                "Latency {}x baseline must trigger detection",
                multiplier
            );
        }
        for multiplier in [1u64, 5, 9] {
            let observed = baseline * multiplier;
            assert!(
                !detection_predicate_latency(observed, baseline, threshold_factor),
                "Latency {}x baseline must not trigger below threshold",
                multiplier
            );
        }
    }

    #[test]
    fn prove_no_false_negative_hidden_process() {
        let proc_count = 100u32;
        let threshold = 2u32;
        for bpf_count in [103u32, 110, 200] {
            assert!(
                detection_predicate_hidden_process(proc_count, bpf_count, threshold),
                "Discrepancy of {} must trigger",
                bpf_count - proc_count
            );
        }
        for bpf_count in [100u32, 101, 102] {
            assert!(
                !detection_predicate_hidden_process(proc_count, bpf_count, threshold),
                "Discrepancy of {} must not trigger",
                bpf_count.saturating_sub(proc_count)
            );
        }
    }

    #[test]
    fn prove_alert_type_complete() {
        let all_types = all_alert_types();
        assert_eq!(all_types.len(), 18);
        for alert_type in &all_types {
            assert!(
                alert_type_has_handler(*alert_type),
                "Alert type {} must have a handler",
                alert_type
            );
        }
    }

    #[test]
    fn prove_memory_forensics_detects_tamper() {
        let baseline = 0xDEADBEEF_u64;
        for tampered in [0u64, 1, 0xCAFEBABE, u64::MAX] {
            if tampered != baseline {
                assert!(
                    detection_predicate_memory_forensics(tampered, baseline),
                    "Tampered checksum {:#x} must be detected",
                    tampered
                );
            }
        }
        assert!(!detection_predicate_memory_forensics(baseline, baseline));
    }

    #[test]
    fn prove_bytecode_tamper_detects_modification() {
        let baseline = 0x12345678_u64;
        for modified in [0u64, 1, 0x87654321, u64::MAX] {
            if modified != baseline {
                assert!(
                    detection_predicate_bytecode_tamper(modified, baseline),
                    "Modified hash {:#x} must be detected",
                    modified
                );
            }
        }
        assert!(!detection_predicate_bytecode_tamper(baseline, baseline));
        assert!(!detection_predicate_bytecode_tamper(999, 0));
    }
}

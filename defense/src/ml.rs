use std::collections::HashMap;

const DEFAULT_NGRAM_SIZE: usize = 3;
const MAX_NGRAM_SIZE: usize = 5;
const DEVIATION_SIGMA_THRESHOLD: f64 = 3.0;
const MIN_TRAINING_SEQUENCES: usize = 50;
const MAX_SIGNATURE_LEN: usize = 16;

#[derive(Debug, Clone)]
pub struct SyscallSequenceModel {
    ngram_counts: HashMap<Vec<u32>, u64>,
    ngram_totals: HashMap<Vec<u32>, u64>,
    ngram_size: usize,
    trained: bool,
    training_scores: Vec<f64>,
    mean_score: f64,
    std_score: f64,
}

impl SyscallSequenceModel {
    pub fn new(ngram_size: usize) -> Self {
        let n = ngram_size.clamp(DEFAULT_NGRAM_SIZE, MAX_NGRAM_SIZE);
        Self {
            ngram_counts: HashMap::new(),
            ngram_totals: HashMap::new(),
            ngram_size: n,
            trained: false,
            training_scores: Vec::new(),
            mean_score: 0.0,
            std_score: 1.0,
        }
    }

    pub fn train(&mut self, sequences: &[Vec<u32>]) {
        self.ngram_counts.clear();
        self.ngram_totals.clear();

        for seq in sequences {
            if seq.len() < self.ngram_size + 1 {
                continue;
            }
            for window in seq.windows(self.ngram_size + 1) {
                let context = window[..self.ngram_size].to_vec();
                let _next = window[self.ngram_size];

                let full_ngram = window.to_vec();
                *self.ngram_counts.entry(full_ngram).or_insert(0) += 1;
                *self.ngram_totals.entry(context).or_insert(0) += 1;
            }
        }

        self.training_scores.clear();
        for seq in sequences {
            let score = self.raw_score(seq);
            if score.is_finite() {
                self.training_scores.push(score);
            }
        }

        if self.training_scores.len() >= MIN_TRAINING_SEQUENCES {
            let n = self.training_scores.len() as f64;
            self.mean_score = self.training_scores.iter().sum::<f64>() / n;
            let variance = self
                .training_scores
                .iter()
                .map(|s| (s - self.mean_score).powi(2))
                .sum::<f64>()
                / n;
            self.std_score = variance.sqrt().max(0.001);
            self.trained = true;
        }
    }

    fn raw_score(&self, sequence: &[u32]) -> f64 {
        if sequence.len() < self.ngram_size + 1 {
            return 0.0;
        }

        let mut log_likelihood = 0.0;
        let mut count = 0u64;

        for window in sequence.windows(self.ngram_size + 1) {
            let context = window[..self.ngram_size].to_vec();
            let full_ngram = window.to_vec();

            let ngram_count = self.ngram_counts.get(&full_ngram).copied().unwrap_or(0);
            let total = self.ngram_totals.get(&context).copied().unwrap_or(0);

            let prob = if total > 0 {
                (ngram_count as f64 + 1.0) / (total as f64 + 256.0)
            } else {
                1.0 / 256.0
            };

            log_likelihood -= prob.ln();
            count += 1;
        }

        if count > 0 {
            log_likelihood / count as f64
        } else {
            0.0
        }
    }

    pub fn score(&self, sequence: &[u32]) -> f64 {
        if !self.trained {
            return 0.0;
        }
        let raw = self.raw_score(sequence);
        (raw - self.mean_score) / self.std_score
    }

    pub fn is_anomalous(&self, sequence: &[u32]) -> bool {
        self.score(sequence) > DEVIATION_SIGMA_THRESHOLD
    }

    pub fn is_trained(&self) -> bool {
        self.trained
    }
}

#[derive(Debug, Clone)]
pub struct DeviationScorer {
    threshold_sigma: f64,
    recent_scores: Vec<f64>,
    max_history: usize,
}

impl DeviationScorer {
    pub fn new() -> Self {
        Self {
            threshold_sigma: DEVIATION_SIGMA_THRESHOLD,
            recent_scores: Vec::new(),
            max_history: 1000,
        }
    }

    pub fn record_score(&mut self, score: f64) {
        self.recent_scores.push(score);
        if self.recent_scores.len() > self.max_history {
            self.recent_scores.remove(0);
        }
    }

    pub fn is_deviation(&self, score: f64) -> bool {
        score > self.threshold_sigma
    }

    pub fn adaptive_threshold(&self) -> f64 {
        if self.recent_scores.len() < 10 {
            return self.threshold_sigma;
        }
        let n = self.recent_scores.len() as f64;
        let mean = self.recent_scores.iter().sum::<f64>() / n;
        let variance = self
            .recent_scores
            .iter()
            .map(|s| (s - mean).powi(2))
            .sum::<f64>()
            / n;
        mean + DEVIATION_SIGMA_THRESHOLD * variance.sqrt().max(0.01)
    }
}

#[derive(Debug, Clone)]
pub struct BytecodeSignature {
    pub opcode_sequence: Vec<u8>,
    pub mask: Vec<u8>,
    pub confidence: f64,
    pub description: String,
}

impl BytecodeSignature {
    pub fn matches(&self, bytecode: &[u8]) -> bool {
        if bytecode.len() < self.opcode_sequence.len() {
            return false;
        }
        for window in bytecode.windows(self.opcode_sequence.len()) {
            let matched = window
                .iter()
                .zip(self.opcode_sequence.iter().zip(self.mask.iter()))
                .all(|(b, (sig, m))| (b & m) == (sig & m));
            if matched {
                return true;
            }
        }
        false
    }
}

#[derive(Debug, Clone)]
pub struct SignatureGenerator {
    signatures: Vec<BytecodeSignature>,
    observed_programs: Vec<Vec<u8>>,
    max_programs: usize,
}

impl SignatureGenerator {
    pub fn new() -> Self {
        Self {
            signatures: Vec::new(),
            observed_programs: Vec::new(),
            max_programs: 256,
        }
    }

    pub fn observe_program(&mut self, bytecode: &[u8]) {
        if self.observed_programs.len() >= self.max_programs {
            self.observed_programs.remove(0);
        }
        self.observed_programs.push(bytecode.to_vec());
    }

    pub fn generate_signatures(&mut self) {
        if self.observed_programs.len() < 2 {
            return;
        }

        let mut opcode_sequences: HashMap<Vec<u8>, u32> = HashMap::new();

        for program in &self.observed_programs {
            let opcodes: Vec<u8> = program.chunks(8).map(|chunk| chunk[0]).collect();

            let sig_len = opcodes.len().min(MAX_SIGNATURE_LEN);
            for window_size in 3..=sig_len {
                for window in opcodes.windows(window_size) {
                    *opcode_sequences.entry(window.to_vec()).or_insert(0) += 1;
                }
            }
        }

        let threshold = (self.observed_programs.len() as u32) / 2;
        let mut candidates: Vec<(Vec<u8>, u32)> = opcode_sequences
            .into_iter()
            .filter(|(_, count)| *count >= threshold.max(2))
            .collect();
        candidates.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then(b.1.cmp(&a.1)));

        self.signatures.clear();
        for (seq, count) in candidates.into_iter().take(32) {
            let confidence = count as f64 / self.observed_programs.len() as f64;
            let mask = vec![0xF0; seq.len()];
            self.signatures.push(BytecodeSignature {
                opcode_sequence: seq,
                mask,
                confidence,
                description: String::from("auto-generated opcode signature"),
            });
        }
    }

    pub fn match_program(&self, bytecode: &[u8]) -> Vec<&BytecodeSignature> {
        self.signatures
            .iter()
            .filter(|sig| sig.matches(bytecode))
            .collect()
    }

    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }
}

#[derive(Debug, Clone)]
pub struct AdversarialMLEngine {
    syscall_model: SyscallSequenceModel,
    deviation_scorer: DeviationScorer,
    signature_gen: SignatureGenerator,
    pid_sequences: HashMap<u32, Vec<u32>>,
    max_sequence_len: usize,
    calibration_sequences: Vec<Vec<u32>>,
    calibrated: bool,
}

impl AdversarialMLEngine {
    pub fn new() -> Self {
        Self {
            syscall_model: SyscallSequenceModel::new(DEFAULT_NGRAM_SIZE),
            deviation_scorer: DeviationScorer::new(),
            signature_gen: SignatureGenerator::new(),
            pid_sequences: HashMap::new(),
            max_sequence_len: 256,
            calibration_sequences: Vec::new(),
            calibrated: false,
        }
    }

    pub fn record_syscall(&mut self, pid: u32, syscall_nr: u32) {
        let seq = self.pid_sequences.entry(pid).or_default();
        seq.push(syscall_nr);
        if seq.len() > self.max_sequence_len {
            seq.remove(0);
        }

        if !self.calibrated {
            if seq.len() == self.max_sequence_len {
                self.calibration_sequences.push(seq.clone());
            }
        }
    }

    pub fn finish_calibration(&mut self) {
        let sequences: Vec<Vec<u32>> = self
            .pid_sequences
            .values()
            .filter(|s| s.len() >= DEFAULT_NGRAM_SIZE + 1)
            .cloned()
            .chain(self.calibration_sequences.drain(..))
            .collect();

        if sequences.len() >= MIN_TRAINING_SEQUENCES {
            self.syscall_model.train(&sequences);
            self.calibrated = true;
        }
    }

    pub fn score_pid(&mut self, pid: u32) -> f64 {
        if !self.calibrated {
            return 0.0;
        }
        let score = self
            .pid_sequences
            .get(&pid)
            .map(|seq| self.syscall_model.score(seq))
            .unwrap_or(0.0);
        self.deviation_scorer.record_score(score);
        score
    }

    pub fn is_anomalous_pid(&mut self, pid: u32) -> bool {
        let score = self.score_pid(pid);
        self.deviation_scorer.is_deviation(score)
    }

    pub fn observe_bytecode(&mut self, bytecode: &[u8]) {
        self.signature_gen.observe_program(bytecode);
    }

    pub fn generate_signatures(&mut self) {
        self.signature_gen.generate_signatures();
    }

    pub fn match_bytecode(&self, bytecode: &[u8]) -> bool {
        !self.signature_gen.match_program(bytecode).is_empty()
    }

    pub fn is_calibrated(&self) -> bool {
        self.calibrated
    }

    pub fn cleanup_pid(&mut self, pid: u32) {
        self.pid_sequences.remove(&pid);
    }

    pub fn active_pids(&self) -> usize {
        self.pid_sequences.len()
    }

    pub fn signature_count(&self) -> usize {
        self.signature_gen.signature_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ngram_training() {
        let mut model = SyscallSequenceModel::new(3);
        let sequences: Vec<Vec<u32>> = (0..100)
            .map(|i| (0..50).map(|j| ((i * 7 + j * 3) % 20) as u32).collect())
            .collect();
        model.train(&sequences);
        assert!(model.is_trained());
    }

    #[test]
    fn test_anomaly_detection() {
        let mut model = SyscallSequenceModel::new(3);
        let normal: Vec<Vec<u32>> = (0..100)
            .map(|_| vec![1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5])
            .collect();
        model.train(&normal);

        let normal_score = model.score(&[1, 2, 3, 4, 5, 1, 2, 3, 4, 5]);
        let anomalous_score = model.score(&[99, 98, 97, 96, 95, 94, 93, 92, 91, 90]);
        assert!(anomalous_score > normal_score);
    }

    #[test]
    fn test_signature_matching() {
        let sig = BytecodeSignature {
            opcode_sequence: vec![0x85, 0x00, 0x06],
            mask: vec![0xFF, 0xFF, 0xFF],
            confidence: 0.9,
            description: String::from("test"),
        };
        assert!(sig.matches(&[0x00, 0x85, 0x00, 0x06, 0x00]));
        assert!(!sig.matches(&[0x00, 0x85, 0x01, 0x06]));
    }

    #[test]
    fn test_engine_calibration() {
        let mut engine = AdversarialMLEngine::new();
        for pid in 0..60u32 {
            for syscall in 0..256u32 {
                engine.record_syscall(pid, syscall % 20);
            }
        }
        engine.finish_calibration();
        assert!(engine.is_calibrated());
    }
}

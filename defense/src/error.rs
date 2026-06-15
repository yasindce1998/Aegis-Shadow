#[derive(Debug, thiserror::Error)]
pub enum DefenseError {
    #[error("failed to load eBPF bytecode: {0}")]
    EbpfLoad(#[from] aya::EbpfError),

    #[error("map operation failed: {0}")]
    Map(#[from] aya::maps::MapError),

    #[error("perf buffer error: {0}")]
    PerfBuffer(#[from] aya::maps::perf::PerfBufferError),

    #[error("program '{program}' attach failed: {source}")]
    Attach {
        program: &'static str,
        #[source]
        source: aya::programs::ProgramError,
    },

    #[error("program '{0}' not found in eBPF object")]
    ProgramNotFound(&'static str),

    #[error("{0}")]
    Io(#[from] std::io::Error),

    #[error("config parse error: {0}")]
    Config(#[from] serde_json::Error),

    #[error("honeypot setup failed: {0}")]
    Honeypot(String),
}

impl DefenseError {
    pub fn attach(program: &'static str, source: aya::programs::ProgramError) -> Self {
        Self::Attach { program, source }
    }
}

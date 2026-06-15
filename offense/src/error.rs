#[derive(Debug, thiserror::Error)]
pub enum OffenseError {
    #[error("failed to load eBPF bytecode: {0}")]
    EbpfLoad(#[from] aya::EbpfError),

    #[error("map operation failed: {0}")]
    Map(#[from] aya::maps::MapError),

    #[error("program '{program}' attach failed: {source}")]
    Attach {
        program: &'static str,
        #[source]
        source: aya::programs::ProgramError,
    },

    #[error("program '{0}' not found in eBPF object")]
    ProgramNotFound(&'static str),

    #[error("program type mismatch for '{0}'")]
    ProgramType(&'static str),

    #[error("{0}")]
    Io(#[from] std::io::Error),

    #[error("configuration error: {0}")]
    Config(String),
}

impl OffenseError {
    pub fn attach(program: &'static str, source: aya::programs::ProgramError) -> Self {
        Self::Attach { program, source }
    }
}

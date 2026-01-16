use thiserror::Error;

#[derive(Debug, Error)]
/// Errors produced by the PCAP/PCAPNG source.
pub enum PcapSourceError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("PCAP parse error ({context}): {message}")]
    Pcap {
        context: &'static str,
        message: String,
    },
}

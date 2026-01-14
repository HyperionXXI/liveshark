use thiserror::Error;

#[derive(Debug, Error)]
pub enum PcapSourceError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("PCAP parse error: {0}")]
    Pcap(String),
}

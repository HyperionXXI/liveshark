//! Packet sources for analysis.
//!
//! Sources abstract over capture inputs (pcap/pcapng today) and keep I/O
//! separate from protocol parsing. A `PacketSource` yields raw packets in
//! capture order with optional timestamps.

mod pcap;

pub use pcap::PcapFileSource;

use pcap_parser::Linktype;
use thiserror::Error;

#[derive(Debug, Clone)]
/// Raw packet event emitted by a `PacketSource`.
pub struct PacketEvent {
    /// Packet timestamp in seconds (if available).
    pub ts: Option<f64>,
    /// Link type for the raw payload.
    pub linktype: Linktype,
    /// Packet bytes.
    pub data: Vec<u8>,
}

/// Abstract packet source for the analysis pipeline.
pub trait PacketSource {
    /// Returns the next packet event, or `None` at end of stream.
    fn next_packet(&mut self) -> Result<Option<PacketEvent>, SourceError>;
}

#[derive(Debug, Error)]
/// Errors produced by `PacketSource` implementations.
pub enum SourceError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("PCAP parse error: {0}")]
    Pcap(String),
}

impl From<pcap::error::PcapSourceError> for SourceError {
    fn from(value: pcap::error::PcapSourceError) -> Self {
        match value {
            pcap::error::PcapSourceError::Io(err) => SourceError::Io(err),
            pcap::error::PcapSourceError::Pcap { context, message } => {
                SourceError::Pcap(format!("{context}: {message}"))
            }
        }
    }
}

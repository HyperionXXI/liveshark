//! Packet sources for analysis.
//!
//! Sources abstract capture inputs (pcap/pcapng today) and keep I/O separate
//! from protocol parsing. A `PacketSource` yields raw packets in capture order
//! with optional timestamps and linktype metadata.
//!
mod pcap;

pub use pcap::PcapFileSource;

use pcap_parser::Linktype;
use thiserror::Error;

/// Raw packet event emitted by a `PacketSource`.
///
/// # Examples
/// ```
/// use liveshark_core::PacketEvent;
/// use pcap_parser::Linktype;
///
/// let event = PacketEvent {
///     ts: Some(1.0),
///     linktype: Linktype::ETHERNET,
///     data: vec![0xde, 0xad, 0xbe, 0xef],
/// };
/// assert_eq!(event.data.len(), 4);
/// ```
#[derive(Debug, Clone)]
pub struct PacketEvent {
    /// Packet timestamp in seconds (if available).
    pub ts: Option<f64>,
    /// Link type for the raw payload.
    pub linktype: Linktype,
    /// Packet bytes.
    pub data: Vec<u8>,
}

/// Abstract packet source for the analysis pipeline.
///
/// # Examples
/// ```
/// use liveshark_core::{PacketEvent, PacketSource, SourceError};
/// use pcap_parser::Linktype;
///
/// struct OnePacket;
///
/// impl PacketSource for OnePacket {
///     fn next_packet(&mut self) -> Result<Option<PacketEvent>, SourceError> {
///         Ok(Some(PacketEvent {
///             ts: Some(0.0),
///             linktype: Linktype::ETHERNET,
///             data: vec![0u8; 4],
///         }))
///     }
/// }
/// ```
pub trait PacketSource {
    /// Returns the next packet event, or `None` at end of stream.
    fn next_packet(&mut self) -> Result<Option<PacketEvent>, SourceError>;
}

/// Errors produced by `PacketSource` implementations.
///
/// # Examples
/// ```
/// use liveshark_core::SourceError;
///
/// let err = SourceError::Pcap("bad pcap".to_string());
/// assert!(err.to_string().contains("PCAP"));
/// ```
#[derive(Debug, Error)]
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

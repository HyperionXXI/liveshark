mod pcap;

pub use pcap::PcapFileSource;

use pcap_parser::Linktype;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct PacketEvent {
    pub ts: Option<f64>,
    pub linktype: Linktype,
    pub data: Vec<u8>,
}

pub trait PacketSource {
    fn next_packet(&mut self) -> Result<Option<PacketEvent>, SourceError>;
}

#[derive(Debug, Error)]
pub enum SourceError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("PCAP parse error: {0}")]
    Pcap(String),
}

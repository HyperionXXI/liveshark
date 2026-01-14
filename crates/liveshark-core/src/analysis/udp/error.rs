use thiserror::Error;

#[derive(Debug, Error)]
pub enum UdpError {
    #[error("packet slice error: {0}")]
    Slice(String),
    #[error("missing network layer in packet")]
    MissingNetworkLayer,
    #[error("missing IP payload in packet")]
    MissingIpPayload,
    #[error("payload too short: need {needed} bytes, got {actual}")]
    TooShort { needed: usize, actual: usize },
}

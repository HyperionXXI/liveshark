use thiserror::Error;

#[derive(Debug, Error)]
pub enum ArtNetError {
    #[error("payload too short: need {needed} bytes, got {actual}")]
    TooShort { needed: usize, actual: usize },
    #[error("invalid ArtDMX length: {length}")]
    InvalidLength { length: u16 },
    #[error("invalid Art-Net universe id: {value}")]
    InvalidUniverseId { value: u16 },
}

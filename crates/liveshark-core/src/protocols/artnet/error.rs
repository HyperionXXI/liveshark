use thiserror::Error;

/// Errors returned by Art-Net parsing and reading.
///
/// Note: this error type lives in an internal module; the example is
/// illustrative and not compiled as a public doctest.
///
/// # Examples
/// ```ignore
/// use liveshark_core::protocols::artnet::error::ArtNetError;
///
/// let err = ArtNetError::InvalidDmxLength { len: 0 };
/// assert!(err.to_string().contains("invalid DMX length"));
/// ```
#[derive(Debug, Error)]
pub enum ArtNetError {
    #[error("payload too short: need {needed} bytes, got {actual}")]
    TooShort { needed: usize, actual: usize },
    #[error("invalid DMX length: {len} (expected even, 2..=512)")]
    InvalidDmxLength { len: usize },
    #[error("invalid Art-Net universe id: {value}")]
    InvalidUniverseId { value: u16 },
    #[error("unsupported Art-Net opcode: {opcode}")]
    UnsupportedOpCode { opcode: u16 },
}

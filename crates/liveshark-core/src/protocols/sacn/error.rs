use thiserror::Error;

/// Errors returned by sACN parsing and reading.
///
/// Note: this error type lives in an internal module; the example is
/// illustrative and not compiled as a public doctest.
///
/// # Examples
/// ```text
/// use liveshark_core::protocols::sacn::error::SacnError;
///
/// let err = SacnError::InvalidStartCode { value: 1 };
/// assert!(err.to_string().contains("invalid start code"));
/// ```
#[derive(Debug, Error)]
pub enum SacnError {
    #[error("payload too short: need {needed} bytes, got {actual}")]
    TooShort { needed: usize, actual: usize },
    #[error("invalid start code: {value}")]
    InvalidStartCode { value: u8 },
    #[error("invalid property value count: {count}")]
    InvalidPropertyValueCount { count: u16 },
    #[error("invalid DMX data length: {length}")]
    InvalidDmxLength { length: u16 },
    #[error("invalid ACN PID")]
    InvalidAcnPid,
    #[error("invalid root vector: {value}")]
    InvalidRootVector { value: u32 },
    #[error("invalid framing vector: {value}")]
    InvalidFramingVector { value: u32 },
    #[error("invalid DMP vector: {value}")]
    InvalidDmpVector { value: u8 },
}

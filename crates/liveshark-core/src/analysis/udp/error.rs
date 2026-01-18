use thiserror::Error;

/// Errors returned by UDP decoding.
///
/// Note: this error type lives in an internal module; the example is
/// illustrative and not compiled as a public doctest.
///
/// # Examples
/// ```text
/// use liveshark_core::analysis::udp::error::UdpError;
///
/// let err = UdpError::MissingNetworkLayer;
/// assert!(err.to_string().contains("missing network layer"));
/// ```
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

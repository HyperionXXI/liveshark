use thiserror::Error;

/// Errors produced by the PCAP/PCAPNG source.
///
/// Note: this error type lives in an internal module; the example is
/// illustrative and not compiled as a public doctest.
///
/// # Examples
/// ```text
/// use liveshark_core::source::pcap::error::PcapSourceError;
///
/// let err = PcapSourceError::Pcap {
///     context: "pcap reader init",
///     message: "bad".to_string(),
/// };
/// assert!(err.to_string().contains("pcap reader init"));
/// ```
#[derive(Debug, Error)]
pub enum PcapSourceError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("PCAP parse error ({context}): {message}")]
    Pcap {
        context: &'static str,
        message: String,
    },
}

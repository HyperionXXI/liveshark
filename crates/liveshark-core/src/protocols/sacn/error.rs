use thiserror::Error;

#[derive(Debug, Error)]
pub enum SacnError {
    #[error("payload too short: need {needed} bytes, got {actual}")]
    TooShort { needed: usize, actual: usize },
    #[error("invalid property value count: {count}")]
    InvalidPropertyValueCount { count: u16 },
    #[error("invalid DMX data length: {length}")]
    InvalidDmxLength { length: u16 },
}

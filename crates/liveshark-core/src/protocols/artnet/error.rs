use thiserror::Error;

#[derive(Debug, Error)]
pub enum ArtNetError {
    #[error("payload too short: need {needed} bytes, got {actual}")]
    TooShort { needed: usize, actual: usize },
}

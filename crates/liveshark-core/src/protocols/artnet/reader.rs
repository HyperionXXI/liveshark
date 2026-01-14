use super::error::ArtNetError;
use super::layout;

pub struct ArtNetReader<'a> {
    payload: &'a [u8],
}

impl<'a> ArtNetReader<'a> {
    pub fn new(payload: &'a [u8]) -> Self {
        Self { payload }
    }

    pub fn require_len(&self, needed: usize) -> Result<(), ArtNetError> {
        if self.payload.len() < needed {
            return Err(ArtNetError::TooShort {
                needed,
                actual: self.payload.len(),
            });
        }
        Ok(())
    }

    pub fn read_u16_le(&self, range: std::ops::Range<usize>) -> Result<u16, ArtNetError> {
        let bytes = self.read_slice(range)?;
        if bytes.len() != 2 {
            return Err(ArtNetError::TooShort {
                needed: 2,
                actual: bytes.len(),
            });
        }
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub fn read_u8(&self, offset: usize) -> Result<u8, ArtNetError> {
        self.payload
            .get(offset)
            .copied()
            .ok_or(ArtNetError::TooShort {
                needed: offset + 1,
                actual: self.payload.len(),
            })
    }

    pub fn read_slice(&self, range: std::ops::Range<usize>) -> Result<&'a [u8], ArtNetError> {
        self.payload
            .get(range.clone())
            .ok_or(ArtNetError::TooShort {
                needed: range.end,
                actual: self.payload.len(),
            })
    }

    pub fn read_signature(&self) -> Result<&'a [u8], ArtNetError> {
        self.read_slice(0..layout::ARTNET_ID.len())
    }
}

use super::error::ArtNetError;
use super::layout;
use crate::protocols::common::reader::optional_nonzero_u8;

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

    pub fn read_optional_nonzero_u8(&self, offset: usize) -> Result<Option<u8>, ArtNetError> {
        let value = self.read_u8(offset)?;
        Ok(optional_nonzero_u8(value))
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

#[cfg(test)]
mod tests {
    use super::ArtNetReader;
    use crate::protocols::artnet::error::ArtNetError;

    #[test]
    fn read_optional_nonzero_u8() {
        let payload = [0x00u8, 0x12u8];
        let reader = ArtNetReader::new(&payload);
        assert_eq!(reader.read_optional_nonzero_u8(0).unwrap(), None);
        assert_eq!(reader.read_optional_nonzero_u8(1).unwrap(), Some(0x12));
    }

    #[test]
    fn read_optional_nonzero_u8_too_short() {
        let payload = [];
        let reader = ArtNetReader::new(&payload);
        let err = reader.read_optional_nonzero_u8(0).unwrap_err();
        assert!(matches!(err, ArtNetError::TooShort { .. }));
    }
}

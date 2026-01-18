use super::error::ArtNetError;
use super::layout;
use crate::protocols::common::reader::optional_nonzero_u8;

/// Safe byte reader for Art-Net payloads.
///
/// Note: this reader lives in an internal module; the example is illustrative
/// and not compiled as a public doctest.
///
/// # Examples
/// ```text
/// use liveshark_core::protocols::artnet::{layout, reader::ArtNetReader};
///
/// let mut payload = vec![0u8; layout::LENGTH_RANGE.end];
/// payload[layout::LENGTH_RANGE.clone()].copy_from_slice(&2u16.to_be_bytes());
/// let reader = ArtNetReader::new(&payload);
/// let length = reader.read_dmx_length(layout::LENGTH_RANGE.clone()).unwrap();
/// assert_eq!(length, 2);
/// ```
pub struct ArtNetReader<'a> {
    payload: &'a [u8],
}

impl<'a> ArtNetReader<'a> {
    pub fn new(payload: &'a [u8]) -> Self {
        Self { payload }
    }

    /// Ensure the payload has at least `needed` bytes.
    pub fn require_len(&self, needed: usize) -> Result<(), ArtNetError> {
        if self.payload.len() < needed {
            return Err(ArtNetError::TooShort {
                needed,
                actual: self.payload.len(),
            });
        }
        Ok(())
    }

    /// Read a little-endian `u16` from the given range.
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

    /// Read and validate the DMX data length (1..=512).
    pub fn read_dmx_length(&self, range: std::ops::Range<usize>) -> Result<usize, ArtNetError> {
        let value = self.read_u16_be(range)?;
        let len = value as usize;
        if !(2..=layout::DMX_MAX_SLOTS).contains(&len) || len % 2 != 0 {
            return Err(ArtNetError::InvalidDmxLength { len });
        }
        Ok(len)
    }

    /// Read the canonical universe identifier and validate its range.
    pub fn read_universe_id(&self, range: std::ops::Range<usize>) -> Result<u16, ArtNetError> {
        let value = self.read_u16_le(range)?;
        if value > 0x7fff {
            return Err(ArtNetError::InvalidUniverseId { value });
        }
        Ok(value)
    }

    /// Read a big-endian `u16` from the given range.
    pub fn read_u16_be(&self, range: std::ops::Range<usize>) -> Result<u16, ArtNetError> {
        let bytes = self.read_slice(range)?;
        if bytes.len() != 2 {
            return Err(ArtNetError::TooShort {
                needed: 2,
                actual: bytes.len(),
            });
        }
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    /// Read a single byte at the given offset.
    pub fn read_u8(&self, offset: usize) -> Result<u8, ArtNetError> {
        self.payload
            .get(offset)
            .copied()
            .ok_or(ArtNetError::TooShort {
                needed: offset + 1,
                actual: self.payload.len(),
            })
    }

    /// Read a byte at the offset, returning `None` for zero.
    pub fn read_optional_nonzero_u8(&self, offset: usize) -> Result<Option<u8>, ArtNetError> {
        let value = self.read_u8(offset)?;
        Ok(optional_nonzero_u8(value))
    }

    /// Read a byte slice from the given range.
    pub fn read_slice(&self, range: std::ops::Range<usize>) -> Result<&'a [u8], ArtNetError> {
        self.payload
            .get(range.clone())
            .ok_or(ArtNetError::TooShort {
                needed: range.end,
                actual: self.payload.len(),
            })
    }

    /// Read the Art-Net signature bytes.
    pub fn read_signature(&self) -> Result<&'a [u8], ArtNetError> {
        self.read_slice(0..layout::ARTNET_ID.len())
    }
}

#[cfg(test)]
mod tests {
    use super::ArtNetReader;
    use crate::protocols::artnet::error::ArtNetError;
    use crate::protocols::artnet::layout;

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

    #[test]
    fn read_universe_id_rejects_out_of_range() {
        let payload = [0x00u8, 0x80u8];
        let reader = ArtNetReader::new(&payload);
        let err = reader.read_universe_id(0..2).unwrap_err();
        assert!(matches!(
            err,
            ArtNetError::InvalidUniverseId { value: 0x8000 }
        ));
    }

    #[test]
    fn read_dmx_length_accepts_valid_range() {
        let mut payload = vec![0u8; layout::LENGTH_RANGE.end];
        payload[layout::LENGTH_RANGE.clone()].copy_from_slice(&2u16.to_be_bytes());
        let reader = ArtNetReader::new(&payload);
        assert_eq!(
            reader
                .read_dmx_length(layout::LENGTH_RANGE.clone())
                .unwrap(),
            2
        );
    }

    #[test]
    fn read_dmx_length_accepts_max() {
        let mut payload = vec![0u8; layout::LENGTH_RANGE.end];
        payload[layout::LENGTH_RANGE.clone()]
            .copy_from_slice(&(layout::DMX_MAX_SLOTS as u16).to_be_bytes());
        let reader = ArtNetReader::new(&payload);
        assert_eq!(
            reader
                .read_dmx_length(layout::LENGTH_RANGE.clone())
                .unwrap(),
            layout::DMX_MAX_SLOTS
        );
    }

    #[test]
    fn read_dmx_length_rejects_zero() {
        let mut payload = vec![0u8; layout::LENGTH_RANGE.end];
        payload[layout::LENGTH_RANGE.clone()].copy_from_slice(&0u16.to_be_bytes());
        let reader = ArtNetReader::new(&payload);
        let err = reader
            .read_dmx_length(layout::LENGTH_RANGE.clone())
            .unwrap_err();
        assert!(matches!(err, ArtNetError::InvalidDmxLength { len: 0 }));
    }

    #[test]
    fn read_dmx_length_rejects_one() {
        let mut payload = vec![0u8; layout::LENGTH_RANGE.end];
        payload[layout::LENGTH_RANGE.clone()].copy_from_slice(&1u16.to_be_bytes());
        let reader = ArtNetReader::new(&payload);
        let err = reader
            .read_dmx_length(layout::LENGTH_RANGE.clone())
            .unwrap_err();
        assert!(matches!(err, ArtNetError::InvalidDmxLength { len: 1 }));
    }

    #[test]
    fn read_dmx_length_rejects_odd_length() {
        let mut payload = vec![0u8; layout::LENGTH_RANGE.end];
        payload[layout::LENGTH_RANGE.clone()].copy_from_slice(&3u16.to_be_bytes());
        let reader = ArtNetReader::new(&payload);
        let err = reader
            .read_dmx_length(layout::LENGTH_RANGE.clone())
            .unwrap_err();
        assert!(matches!(err, ArtNetError::InvalidDmxLength { len: 3 }));
    }

    #[test]
    fn read_dmx_length_rejects_odd_max_minus_one() {
        let value = (layout::DMX_MAX_SLOTS as u16) - 1;
        let mut payload = vec![0u8; layout::LENGTH_RANGE.end];
        payload[layout::LENGTH_RANGE.clone()].copy_from_slice(&value.to_be_bytes());
        let reader = ArtNetReader::new(&payload);
        let err = reader
            .read_dmx_length(layout::LENGTH_RANGE.clone())
            .unwrap_err();
        assert!(matches!(err, ArtNetError::InvalidDmxLength { len } if len == value as usize));
    }

    #[test]
    fn read_dmx_length_rejects_too_large() {
        let value = (layout::DMX_MAX_SLOTS as u16) + 1;
        let mut payload = vec![0u8; layout::LENGTH_RANGE.end];
        payload[layout::LENGTH_RANGE.clone()].copy_from_slice(&value.to_be_bytes());
        let reader = ArtNetReader::new(&payload);
        let err = reader
            .read_dmx_length(layout::LENGTH_RANGE.clone())
            .unwrap_err();
        assert!(matches!(err, ArtNetError::InvalidDmxLength { len } if len == value as usize));
    }
}

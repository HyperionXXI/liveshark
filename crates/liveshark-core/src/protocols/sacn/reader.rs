use super::error::SacnError;
use super::layout;
use crate::protocols::common::reader::optional_nonzero_u8;

pub struct SacnReader<'a> {
    payload: &'a [u8],
}

impl<'a> SacnReader<'a> {
    pub fn new(payload: &'a [u8]) -> Self {
        Self { payload }
    }

    pub fn require_len(&self, needed: usize) -> Result<(), SacnError> {
        if self.payload.len() < needed {
            return Err(SacnError::TooShort {
                needed,
                actual: self.payload.len(),
            });
        }
        Ok(())
    }

    pub fn read_u8(&self, offset: usize) -> Result<u8, SacnError> {
        self.payload
            .get(offset)
            .copied()
            .ok_or(SacnError::TooShort {
                needed: offset + 1,
                actual: self.payload.len(),
            })
    }

    pub fn read_u16_be(&self, range: std::ops::Range<usize>) -> Result<u16, SacnError> {
        let bytes = self.read_slice(range)?;
        if bytes.len() != 2 {
            return Err(SacnError::TooShort {
                needed: 2,
                actual: bytes.len(),
            });
        }
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub fn read_u32_be(&self, range: std::ops::Range<usize>) -> Result<u32, SacnError> {
        let bytes = self.read_slice(range)?;
        if bytes.len() != 4 {
            return Err(SacnError::TooShort {
                needed: 4,
                actual: bytes.len(),
            });
        }
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn read_slice(&self, range: std::ops::Range<usize>) -> Result<&'a [u8], SacnError> {
        self.payload.get(range.clone()).ok_or(SacnError::TooShort {
            needed: range.end,
            actual: self.payload.len(),
        })
    }

    pub fn read_ascii_string(&self, range: std::ops::Range<usize>) -> Result<String, SacnError> {
        let bytes = self.read_slice(range)?;
        let raw = String::from_utf8_lossy(bytes);
        Ok(raw.trim_end_matches('\0').trim().to_string())
    }

    pub fn read_cid_hex(&self) -> Result<String, SacnError> {
        let bytes = self.read_slice(layout::CID_RANGE.clone())?;
        Ok(bytes.iter().map(|b| format!("{:02x}", b)).collect())
    }

    pub fn read_optional_nonzero_u8(&self, offset: usize) -> Result<Option<u8>, SacnError> {
        let value = self.read_u8(offset)?;
        Ok(optional_nonzero_u8(value))
    }

    pub fn read_optional_ascii_string(
        &self,
        range: std::ops::Range<usize>,
    ) -> Result<Option<String>, SacnError> {
        let value = self.read_ascii_string(range)?;
        if value.is_empty() {
            Ok(None)
        } else {
            Ok(Some(value))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SacnReader;
    use crate::protocols::sacn::error::SacnError;

    #[test]
    fn read_optional_nonzero_u8() {
        let payload = [0x00u8, 0x12u8];
        let reader = SacnReader::new(&payload);
        assert_eq!(reader.read_optional_nonzero_u8(0).unwrap(), None);
        assert_eq!(reader.read_optional_nonzero_u8(1).unwrap(), Some(0x12));
    }

    #[test]
    fn read_optional_nonzero_u8_too_short() {
        let payload = [];
        let reader = SacnReader::new(&payload);
        let err = reader.read_optional_nonzero_u8(0).unwrap_err();
        assert!(matches!(err, SacnError::TooShort { .. }));
    }

    #[test]
    fn read_optional_ascii_string() {
        let payload = [b't', b'e', b's', b't', 0x00];
        let reader = SacnReader::new(&payload);
        let value = reader.read_optional_ascii_string(0..payload.len()).unwrap();
        assert_eq!(value.as_deref(), Some("test"));

        let empty = [0x00u8; 4];
        let reader = SacnReader::new(&empty);
        let value = reader.read_optional_ascii_string(0..empty.len()).unwrap();
        assert!(value.is_none());
    }

    #[test]
    fn read_optional_ascii_string_too_short() {
        let payload = [];
        let reader = SacnReader::new(&payload);
        let err = reader.read_optional_ascii_string(0..1).unwrap_err();
        assert!(matches!(err, SacnError::TooShort { .. }));
    }
}

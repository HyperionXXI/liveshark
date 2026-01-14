use super::error::SacnError;
use super::layout;

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
}

use super::error::UdpError;
use super::layout;

pub struct UdpReader<'a> {
    payload: &'a [u8],
}

impl<'a> UdpReader<'a> {
    pub fn new(payload: &'a [u8]) -> Self {
        Self { payload }
    }

    pub fn require_len(&self, needed: usize) -> Result<(), UdpError> {
        if self.payload.len() < needed {
            return Err(UdpError::TooShort {
                needed,
                actual: self.payload.len(),
            });
        }
        Ok(())
    }

    pub fn payload_without_header(&self) -> Result<&'a [u8], UdpError> {
        self.require_len(layout::UDP_HEADER_LEN)?;
        self.payload
            .get(layout::UDP_HEADER_LEN..)
            .ok_or(UdpError::TooShort {
                needed: layout::UDP_HEADER_LEN,
                actual: self.payload.len(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::UdpReader;
    use crate::analysis::udp::error::UdpError;

    #[test]
    fn payload_without_header_ok() {
        let payload = [0u8; 12];
        let reader = UdpReader::new(&payload);
        let payload = reader.payload_without_header().unwrap();
        assert_eq!(payload.len(), 4);
    }

    #[test]
    fn payload_without_header_too_short() {
        let payload = [0u8; 7];
        let reader = UdpReader::new(&payload);
        let err = reader.payload_without_header().unwrap_err();
        assert!(matches!(err, UdpError::TooShort { .. }));
    }
}

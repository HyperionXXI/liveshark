use std::io::{Read, Seek, SeekFrom};

use super::error::PcapSourceError;
use super::layout;

pub fn read_magic_and_rewind<R: Read + Seek>(reader: &mut R) -> Result<[u8; 4], PcapSourceError> {
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    reader.seek(SeekFrom::Start(0))?;
    Ok(magic)
}

pub fn is_pcapng_magic(magic: &[u8; 4]) -> bool {
    magic == &layout::PCAPNG_MAGIC
}

#[cfg(test)]
mod tests {
    use super::{is_pcapng_magic, read_magic_and_rewind};
    use crate::source::pcap::error::PcapSourceError;
    use std::io::Cursor;
    use std::io::Read;

    #[test]
    fn detect_pcapng_magic() {
        let data = super::layout::PCAPNG_MAGIC;
        assert!(is_pcapng_magic(&data));
    }

    #[test]
    fn read_magic_rewinds() {
        let bytes = [0x0a, 0x0d, 0x0d, 0x0a, 0x01];
        let mut cursor = Cursor::new(bytes);
        let magic = read_magic_and_rewind(&mut cursor).unwrap();
        assert_eq!(magic, [0x0a, 0x0d, 0x0d, 0x0a]);
        let mut buf = [0u8; 1];
        cursor.read_exact(&mut buf).unwrap();
        assert_eq!(buf[0], 0x0a);
    }

    #[test]
    fn read_magic_too_short() {
        let bytes = [0x0a, 0x0d, 0x0d];
        let mut cursor = Cursor::new(bytes);
        let err = read_magic_and_rewind(&mut cursor).unwrap_err();
        assert!(matches!(err, PcapSourceError::Io(_)));
    }
}

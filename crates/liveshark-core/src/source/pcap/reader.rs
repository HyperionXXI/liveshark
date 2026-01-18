use std::io::{Read, Seek, SeekFrom};

use super::error::PcapSourceError;
use super::layout;
use pcap_parser::Linktype;

/// Read the magic bytes and rewind the reader to the start.
///
/// # Examples
/// This helper is part of an internal module, so the example is marked as
/// text example.
/// ```text
/// use liveshark_core::source::pcap::reader::read_magic_and_rewind;
/// use std::io::Cursor;
///
/// let bytes = [0x0a, 0x0d, 0x0d, 0x0a, 0x01];
/// let mut cursor = Cursor::new(bytes);
/// let magic = read_magic_and_rewind(&mut cursor).unwrap();
/// assert_eq!(magic, [0x0a, 0x0d, 0x0d, 0x0a]);
/// ```
///
/// # Errors
/// Returns `PcapSourceError` when the reader cannot be read or rewound.
pub fn read_magic_and_rewind<R: Read + Seek>(reader: &mut R) -> Result<[u8; 4], PcapSourceError> {
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    reader.seek(SeekFrom::Start(0))?;
    Ok(magic)
}

/// Check whether the magic bytes match PCAPNG.
///
/// # Examples
/// This helper is part of an internal module, so the example is marked as
/// text example.
/// ```text
/// use liveshark_core::source::pcap::reader::is_pcapng_magic;
///
/// let magic = [0x0a, 0x0d, 0x0d, 0x0a];
/// assert!(is_pcapng_magic(&magic));
/// ```
pub fn is_pcapng_magic(magic: &[u8; 4]) -> bool {
    magic == &layout::PCAPNG_MAGIC
}

/// Resolve the linktype for a given interface id, defaulting to Ethernet.
///
/// # Examples
/// This helper is part of an internal module, so the example is marked as
/// text example.
/// ```text
/// use liveshark_core::source::pcap::reader::linktype_for_interface;
/// use pcap_parser::Linktype;
///
/// let linktypes = [Linktype::RAW];
/// assert_eq!(linktype_for_interface(&linktypes, 0), Linktype::RAW);
/// assert_eq!(linktype_for_interface(&linktypes, 1), Linktype::ETHERNET);
/// ```
pub fn linktype_for_interface(linktypes: &[Linktype], if_id: u32) -> Linktype {
    linktypes
        .get(if_id as usize)
        .copied()
        .unwrap_or(Linktype::ETHERNET)
}

/// Convert PCAPNG high/low timestamp to seconds.
///
/// # Examples
/// This helper is part of an internal module, so the example is marked as
/// text example.
/// ```text
/// use liveshark_core::source::pcap::reader::pcapng_ts_to_seconds;
///
/// let seconds = pcapng_ts_to_seconds(0, 1_500_000);
/// assert!((seconds - 1.5).abs() < f64::EPSILON);
/// ```
pub fn pcapng_ts_to_seconds(ts_high: u32, ts_low: u32) -> f64 {
    let ts = ((ts_high as u64) << 32) | (ts_low as u64);
    ts as f64 * 1e-6
}

#[cfg(test)]
mod tests {
    use super::{is_pcapng_magic, linktype_for_interface, read_magic_and_rewind};
    use crate::source::pcap::error::PcapSourceError;
    use pcap_parser::Linktype;
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

    #[test]
    fn linktype_defaults_to_ethernet_when_missing() {
        let linktypes = [Linktype::RAW];
        assert_eq!(linktype_for_interface(&linktypes, 0), Linktype::RAW);
        assert_eq!(linktype_for_interface(&linktypes, 1), Linktype::ETHERNET);
    }

    #[test]
    fn pcapng_ts_to_seconds_converts_microseconds() {
        let seconds = super::pcapng_ts_to_seconds(0, 1_500_000);
        assert!((seconds - 1.5).abs() < f64::EPSILON);
    }
}

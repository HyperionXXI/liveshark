use super::error::ArtNetError;
use super::layout;
use super::reader::ArtNetReader;

#[derive(Debug)]
pub struct ArtDmx {
    pub universe: u16,
    pub sequence: Option<u8>,
    pub slots: [u8; layout::DMX_MAX_SLOTS],
}

pub fn parse_artdmx(payload: &[u8]) -> Result<Option<ArtDmx>, ArtNetError> {
    let reader = ArtNetReader::new(payload);
    reader.require_len(layout::DMX_DATA_OFFSET)?;

    let signature = reader.read_signature()?;
    if signature != layout::ARTNET_ID {
        return Ok(None);
    }

    let opcode = reader.read_u16_le(layout::OP_CODE_RANGE.clone())?;
    if opcode != layout::ARTDMX_OPCODE {
        return Ok(None);
    }

    let sequence = reader.read_optional_nonzero_u8(layout::SEQUENCE_OFFSET)?;
    let universe = reader.read_u16_le(layout::UNIVERSE_RANGE.clone())?;
    let length = reader.read_u16_be(layout::LENGTH_RANGE.clone())?;
    if length == 0 || length as usize > layout::DMX_MAX_SLOTS {
        return Err(ArtNetError::InvalidLength { length });
    }

    let data_len = length as usize;
    let needed = layout::DMX_DATA_OFFSET
        .checked_add(data_len)
        .ok_or(ArtNetError::InvalidLength { length })?;
    reader.require_len(needed)?;
    let data = reader.read_slice(layout::DMX_DATA_OFFSET..needed)?;
    let mut slots = [0u8; layout::DMX_MAX_SLOTS];
    slots[..data_len].copy_from_slice(data);

    Ok(Some(ArtDmx {
        universe,
        sequence,
        slots,
    }))
}

#[cfg(test)]
mod tests {
    use super::parse_artdmx;
    use crate::protocols::artnet::layout;

    #[test]
    fn parse_valid_artdmx() {
        let length = 4u16;
        let mut payload = vec![0u8; layout::DMX_DATA_OFFSET + length as usize];
        payload[..layout::ARTNET_ID.len()].copy_from_slice(layout::ARTNET_ID);
        payload[layout::OP_CODE_RANGE.clone()]
            .copy_from_slice(&layout::ARTDMX_OPCODE.to_le_bytes());
        payload[layout::SEQUENCE_OFFSET] = 0x12;
        payload[layout::UNIVERSE_RANGE.clone()].copy_from_slice(&1u16.to_le_bytes());
        payload[layout::LENGTH_RANGE.clone()].copy_from_slice(&length.to_be_bytes());
        payload[layout::DMX_DATA_OFFSET..layout::DMX_DATA_OFFSET + 4]
            .copy_from_slice(&[1, 2, 3, 4]);

        let parsed = parse_artdmx(&payload).unwrap();
        assert!(parsed.is_some());
        let parsed = parsed.unwrap();
        assert_eq!(parsed.universe, 1);
        assert_eq!(parsed.sequence, Some(0x12));
        assert_eq!(&parsed.slots[..4], &[1, 2, 3, 4]);
        assert_eq!(parsed.slots[4], 0);
    }

    #[test]
    fn parse_non_artnet() {
        let payload = vec![0u8; layout::DMX_DATA_OFFSET];
        let parsed = parse_artdmx(&payload).unwrap();
        assert!(parsed.is_none());
    }

    #[test]
    fn parse_short_payload() {
        let payload = vec![0u8; layout::DMX_DATA_OFFSET - 1];
        let err = parse_artdmx(&payload).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("payload too short"));
    }

    #[test]
    fn parse_invalid_length() {
        let length = (layout::DMX_MAX_SLOTS as u16) + 1;
        let mut payload = vec![0u8; layout::DMX_DATA_OFFSET];
        payload[..layout::ARTNET_ID.len()].copy_from_slice(layout::ARTNET_ID);
        payload[layout::OP_CODE_RANGE.clone()]
            .copy_from_slice(&layout::ARTDMX_OPCODE.to_le_bytes());
        payload[layout::LENGTH_RANGE.clone()].copy_from_slice(&length.to_be_bytes());

        let err = parse_artdmx(&payload).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("invalid ArtDMX length"));
    }
}

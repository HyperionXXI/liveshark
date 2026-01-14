use super::error::ArtNetError;
use super::layout;
use super::reader::ArtNetReader;

#[derive(Debug)]
pub struct ArtDmx {
    pub universe: u16,
    pub sequence: Option<u8>,
}

pub fn parse_artdmx(payload: &[u8]) -> Result<Option<ArtDmx>, ArtNetError> {
    let reader = ArtNetReader::new(payload);
    reader.require_len(layout::LENGTH_RANGE.end)?;

    let signature = reader.read_signature()?;
    if signature != layout::ARTNET_ID {
        return Ok(None);
    }

    let opcode = reader.read_u16_le(layout::OP_CODE_RANGE.clone())?;
    if opcode != layout::ARTDMX_OPCODE {
        return Ok(None);
    }

    let sequence = reader.read_u8(layout::SEQUENCE_OFFSET)?;
    let universe = reader.read_u16_le(layout::UNIVERSE_RANGE.clone())?;
    let sequence = parse_optional_nonzero(sequence);

    Ok(Some(ArtDmx { universe, sequence }))
}

fn parse_optional_nonzero(value: u8) -> Option<u8> {
    if value == 0 { None } else { Some(value) }
}

#[cfg(test)]
mod tests {
    use super::parse_artdmx;
    use crate::protocols::artnet::layout;

    #[test]
    fn parse_valid_artdmx() {
        let mut payload = vec![0u8; layout::LENGTH_RANGE.end];
        payload[..layout::ARTNET_ID.len()].copy_from_slice(layout::ARTNET_ID);
        payload[layout::OP_CODE_RANGE.clone()]
            .copy_from_slice(&layout::ARTDMX_OPCODE.to_le_bytes());
        payload[layout::SEQUENCE_OFFSET] = 0x12;
        payload[layout::UNIVERSE_RANGE.clone()].copy_from_slice(&1u16.to_le_bytes());

        let parsed = parse_artdmx(&payload).unwrap();
        assert!(parsed.is_some());
        let parsed = parsed.unwrap();
        assert_eq!(parsed.universe, 1);
        assert_eq!(parsed.sequence, Some(0x12));
    }

    #[test]
    fn parse_non_artnet() {
        let payload = vec![0u8; layout::LENGTH_RANGE.end];
        let parsed = parse_artdmx(&payload).unwrap();
        assert!(parsed.is_none());
    }

    #[test]
    fn parse_short_payload() {
        let payload = vec![0u8; layout::LENGTH_RANGE.end - 1];
        let err = parse_artdmx(&payload).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("payload too short"));
    }
}

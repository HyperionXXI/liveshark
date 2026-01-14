use super::error::SacnError;
use super::layout;
use super::reader::SacnReader;

pub struct SacnDmx {
    pub universe: u16,
    pub cid: String,
    pub source_name: Option<String>,
    pub sequence: Option<u8>,
}

pub fn parse_sacn_dmx(payload: &[u8]) -> Result<Option<SacnDmx>, SacnError> {
    let reader = SacnReader::new(payload);
    reader.require_len(layout::MIN_LEN)?;

    let preamble = reader.read_u16_be(layout::PREAMBLE_SIZE_RANGE.clone())?;
    let postamble = reader.read_u16_be(layout::POSTAMBLE_SIZE_RANGE.clone())?;
    if preamble != layout::PREAMBLE_SIZE || postamble != layout::POSTAMBLE_SIZE {
        return Ok(None);
    }

    let acn_pid = reader.read_slice(layout::ACN_PID_RANGE.clone())?;
    if acn_pid != layout::ACN_PID {
        return Ok(None);
    }

    let root_vector = reader.read_u32_be(layout::ROOT_VECTOR_RANGE.clone())?;
    if root_vector != layout::ROOT_VECTOR_DATA {
        return Ok(None);
    }

    let framing_vector = reader.read_u32_be(layout::FRAMING_VECTOR_RANGE.clone())?;
    if framing_vector != layout::FRAMING_VECTOR_DMX {
        return Ok(None);
    }

    let dmp_vector = reader.read_u8(layout::DMP_VECTOR_OFFSET)?;
    if dmp_vector != layout::DMP_VECTOR_SET_PROPERTY {
        return Ok(None);
    }

    let universe = reader.read_u16_be(layout::UNIVERSE_RANGE.clone())?;
    let cid = reader.read_cid_hex()?;
    let source_name =
        parse_optional_string(reader.read_ascii_string(layout::SOURCE_NAME_RANGE.clone())?);
    let sequence = parse_optional_nonzero(reader.read_u8(layout::SEQUENCE_OFFSET)?);

    Ok(Some(SacnDmx {
        universe,
        cid,
        source_name,
        sequence,
    }))
}

fn parse_optional_string(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

fn parse_optional_nonzero(value: u8) -> Option<u8> {
    if value == 0 { None } else { Some(value) }
}

#[cfg(test)]
mod tests {
    use super::parse_sacn_dmx;
    use crate::protocols::sacn::layout;

    #[test]
    fn parse_valid_sacn() {
        let mut payload = vec![0u8; layout::MIN_LEN];
        payload[layout::PREAMBLE_SIZE_RANGE.clone()]
            .copy_from_slice(&layout::PREAMBLE_SIZE.to_be_bytes());
        payload[layout::POSTAMBLE_SIZE_RANGE.clone()]
            .copy_from_slice(&layout::POSTAMBLE_SIZE.to_be_bytes());
        payload[layout::ACN_PID_RANGE.clone()].copy_from_slice(layout::ACN_PID);
        payload[layout::ROOT_VECTOR_RANGE.clone()]
            .copy_from_slice(&layout::ROOT_VECTOR_DATA.to_be_bytes());
        payload[layout::FRAMING_VECTOR_RANGE.clone()]
            .copy_from_slice(&layout::FRAMING_VECTOR_DMX.to_be_bytes());
        payload[layout::DMP_VECTOR_OFFSET] = layout::DMP_VECTOR_SET_PROPERTY;
        payload[layout::UNIVERSE_RANGE.clone()].copy_from_slice(&1u16.to_be_bytes());
        payload[layout::SEQUENCE_OFFSET] = 0x01;

        let parsed = parse_sacn_dmx(&payload).unwrap();
        assert!(parsed.is_some());
        let parsed = parsed.unwrap();
        assert_eq!(parsed.universe, 1);
        assert_eq!(parsed.sequence, Some(0x01));
    }

    #[test]
    fn parse_non_sacn() {
        let payload = vec![0u8; layout::MIN_LEN];
        let parsed = parse_sacn_dmx(&payload).unwrap();
        assert!(parsed.is_none());
    }

    #[test]
    fn parse_short_payload() {
        let payload = vec![0u8; layout::MIN_LEN - 1];
        let err = parse_sacn_dmx(&payload).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("payload too short"));
    }
}

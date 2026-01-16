use super::error::SacnError;
use super::layout;
use super::reader::SacnReader;

#[derive(Debug)]
pub struct SacnDmx {
    pub universe: u16,
    pub cid: String,
    pub source_name: Option<String>,
    pub sequence: Option<u8>,
    pub slots: Vec<u8>,
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
        return Err(SacnError::InvalidAcnPid);
    }

    let root_vector = reader.read_u32_be(layout::ROOT_VECTOR_RANGE.clone())?;
    if root_vector != layout::ROOT_VECTOR_DATA {
        return Err(SacnError::InvalidRootVector { value: root_vector });
    }

    let framing_vector = reader.read_u32_be(layout::FRAMING_VECTOR_RANGE.clone())?;
    if framing_vector != layout::FRAMING_VECTOR_DMX {
        return Err(SacnError::InvalidFramingVector {
            value: framing_vector,
        });
    }

    let dmp_vector = reader.read_u8(layout::DMP_VECTOR_OFFSET)?;
    if dmp_vector != layout::DMP_VECTOR_SET_PROPERTY {
        return Err(SacnError::InvalidDmpVector { value: dmp_vector });
    }

    reader.read_start_code()?;

    let universe = reader.read_u16_be(layout::UNIVERSE_RANGE.clone())?;
    let cid = reader.read_cid_hex()?;
    let source_name = reader.read_optional_ascii_string(layout::SOURCE_NAME_RANGE.clone())?;
    let sequence = reader.read_optional_nonzero_u8(layout::SEQUENCE_OFFSET)?;
    let data_len = reader.read_dmx_data_len()?;
    let slots = if data_len > 0 {
        let needed = layout::DMX_DATA_OFFSET
            .checked_add(data_len)
            .ok_or(SacnError::InvalidDmxLength { length: 0 })?;
        let data = reader.read_slice(layout::DMX_DATA_OFFSET..needed)?;
        data.to_vec()
    } else {
        Vec::new()
    };

    Ok(Some(SacnDmx {
        universe,
        cid,
        source_name,
        sequence,
        slots,
    }))
}

#[cfg(test)]
mod tests {
    use super::parse_sacn_dmx;
    use crate::protocols::sacn::error::SacnError;
    use crate::protocols::sacn::layout;

    #[test]
    fn parse_valid_sacn() {
        let count = 3u16;
        let mut payload = vec![0u8; layout::DMX_DATA_OFFSET + (count - 1) as usize];
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
        payload[layout::START_CODE_OFFSET] = 0x00;
        payload[layout::SEQUENCE_OFFSET] = 0x01;
        payload[layout::DMP_PROPERTY_VALUE_COUNT_RANGE.clone()]
            .copy_from_slice(&count.to_be_bytes());
        payload[layout::START_CODE_OFFSET] = 0x00;
        payload[layout::DMX_DATA_OFFSET..layout::DMX_DATA_OFFSET + 2].copy_from_slice(&[1, 2]);

        let parsed = parse_sacn_dmx(&payload).unwrap();
        assert!(parsed.is_some());
        let parsed = parsed.unwrap();
        assert_eq!(parsed.universe, 1);
        assert_eq!(parsed.sequence, Some(0x01));
        assert_eq!(&parsed.slots[..2], &[1, 2]);
        assert_eq!(parsed.slots.len(), 2);
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

    #[test]
    fn parse_invalid_property_value_count() {
        let mut payload = vec![0u8; layout::DMX_DATA_OFFSET];
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
        payload[layout::START_CODE_OFFSET] = 0x00;
        payload[layout::DMP_PROPERTY_VALUE_COUNT_RANGE.clone()]
            .copy_from_slice(&0u16.to_be_bytes());

        let err = parse_sacn_dmx(&payload).unwrap_err();
        assert!(matches!(
            err,
            SacnError::InvalidPropertyValueCount { count: 0 }
        ));
    }

    #[test]
    fn parse_invalid_start_code() {
        let mut payload = vec![0u8; layout::DMX_DATA_OFFSET];
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
        payload[layout::START_CODE_OFFSET] = 0x01;
        payload[layout::DMP_PROPERTY_VALUE_COUNT_RANGE.clone()]
            .copy_from_slice(&1u16.to_be_bytes());

        let err = parse_sacn_dmx(&payload).unwrap_err();
        assert!(matches!(err, SacnError::InvalidStartCode { value: 0x01 }));
    }

    #[test]
    fn parse_invalid_acn_pid() {
        let mut payload = vec![0u8; layout::MIN_LEN];
        payload[layout::PREAMBLE_SIZE_RANGE.clone()]
            .copy_from_slice(&layout::PREAMBLE_SIZE.to_be_bytes());
        payload[layout::POSTAMBLE_SIZE_RANGE.clone()]
            .copy_from_slice(&layout::POSTAMBLE_SIZE.to_be_bytes());
        payload[layout::ACN_PID_RANGE.clone()].copy_from_slice(b"ASC-E1.17\x01\x02\x03");

        let err = parse_sacn_dmx(&payload).unwrap_err();
        assert!(matches!(err, SacnError::InvalidAcnPid));
    }

    #[test]
    fn parse_invalid_root_vector() {
        let mut payload = vec![0u8; layout::MIN_LEN];
        payload[layout::PREAMBLE_SIZE_RANGE.clone()]
            .copy_from_slice(&layout::PREAMBLE_SIZE.to_be_bytes());
        payload[layout::POSTAMBLE_SIZE_RANGE.clone()]
            .copy_from_slice(&layout::POSTAMBLE_SIZE.to_be_bytes());
        payload[layout::ACN_PID_RANGE.clone()].copy_from_slice(layout::ACN_PID);
        payload[layout::ROOT_VECTOR_RANGE.clone()].copy_from_slice(&0x0000_0001u32.to_be_bytes());

        let err = parse_sacn_dmx(&payload).unwrap_err();
        assert!(matches!(err, SacnError::InvalidRootVector { value: 1 }));
    }

    #[test]
    fn parse_invalid_framing_vector() {
        let mut payload = vec![0u8; layout::MIN_LEN];
        payload[layout::PREAMBLE_SIZE_RANGE.clone()]
            .copy_from_slice(&layout::PREAMBLE_SIZE.to_be_bytes());
        payload[layout::POSTAMBLE_SIZE_RANGE.clone()]
            .copy_from_slice(&layout::POSTAMBLE_SIZE.to_be_bytes());
        payload[layout::ACN_PID_RANGE.clone()].copy_from_slice(layout::ACN_PID);
        payload[layout::ROOT_VECTOR_RANGE.clone()]
            .copy_from_slice(&layout::ROOT_VECTOR_DATA.to_be_bytes());
        payload[layout::FRAMING_VECTOR_RANGE.clone()]
            .copy_from_slice(&0x0000_0001u32.to_be_bytes());

        let err = parse_sacn_dmx(&payload).unwrap_err();
        assert!(matches!(err, SacnError::InvalidFramingVector { value: 1 }));
    }

    #[test]
    fn parse_invalid_dmp_vector() {
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
        payload[layout::DMP_VECTOR_OFFSET] = 0x00;

        let err = parse_sacn_dmx(&payload).unwrap_err();
        assert!(matches!(err, SacnError::InvalidDmpVector { value: 0 }));
    }

    #[test]
    fn parse_property_value_count_too_large() {
        let mut payload = vec![0u8; layout::DMX_DATA_OFFSET];
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
        payload[layout::START_CODE_OFFSET] = 0x00;
        payload[layout::DMP_PROPERTY_VALUE_COUNT_RANGE.clone()]
            .copy_from_slice(&(layout::DMX_MAX_SLOTS as u16 + 2).to_be_bytes());

        let err = parse_sacn_dmx(&payload).unwrap_err();
        assert!(matches!(
            err,
            SacnError::InvalidPropertyValueCount { count: 514 }
        ));
    }
}

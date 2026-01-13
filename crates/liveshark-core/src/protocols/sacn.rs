pub struct SacnDmx {
    pub universe: u16,
    pub cid: String,
    pub source_name: Option<String>,
}

pub fn parse_sacn_dmx(payload: &[u8]) -> Option<SacnDmx> {
    if payload.len() < 126 {
        return None;
    }
    if payload[0..2] != [0x00, 0x10] || payload[2..4] != [0x00, 0x00] {
        return None;
    }
    if &payload[4..16] != b"ASC-E1.17\0\0\0" {
        return None;
    }

    let root_vector = u32::from_be_bytes([payload[18], payload[19], payload[20], payload[21]]);
    if root_vector != 0x0000_0004 {
        return None;
    }

    let framing_vector = u32::from_be_bytes([payload[40], payload[41], payload[42], payload[43]]);
    if framing_vector != 0x0000_0002 {
        return None;
    }

    let dmp_vector = payload[117];
    if dmp_vector != 0x02 {
        return None;
    }

    let universe = u16::from_be_bytes([payload[113], payload[114]]);
    let cid = format_cid(&payload[22..38]);
    let source_name = parse_source_name(&payload[44..108]);

    Some(SacnDmx {
        universe,
        cid,
        source_name,
    })
}

fn format_cid(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

fn parse_source_name(bytes: &[u8]) -> Option<String> {
    let raw = String::from_utf8_lossy(bytes);
    let trimmed = raw.trim_end_matches('\0').trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

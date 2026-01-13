pub struct ArtDmx {
    pub universe: u16,
}

pub fn parse_artdmx(payload: &[u8]) -> Option<ArtDmx> {
    if payload.len() < 18 {
        return None;
    }
    if &payload[0..8] != b"Art-Net\0" {
        return None;
    }
    let opcode = u16::from_le_bytes([payload[8], payload[9]]);
    if opcode != 0x5000 {
        return None;
    }
    let universe = u16::from_le_bytes([payload[14], payload[15]]);
    Some(ArtDmx { universe })
}

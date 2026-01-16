use std::fs;
use std::path::{Path, PathBuf};

const ETHERTYPE_IPV4: u16 = 0x0800;
const UDP_PROTO: u8 = 17;
const ARTNET_PORT: u16 = 6454;
const SACN_PORT: u16 = 5568;

const ARTNET_ID: &[u8; 8] = b"Art-Net\0";
const ARTNET_OP_CODE_RANGE: std::ops::Range<usize> = 8..10;
const ARTNET_SEQUENCE_OFFSET: usize = 12;
const ARTNET_UNIVERSE_RANGE: std::ops::Range<usize> = 14..16;
const ARTNET_LENGTH_RANGE: std::ops::Range<usize> = 16..18;
const ARTNET_DMX_DATA_OFFSET: usize = 18;
const ARTNET_ARTDMX_OPCODE: u16 = 0x5000;
const ARTNET_DMX_MAX_SLOTS: usize = 512;

const SACN_PREAMBLE_SIZE_RANGE: std::ops::Range<usize> = 0..2;
const SACN_POSTAMBLE_SIZE_RANGE: std::ops::Range<usize> = 2..4;
const SACN_ACN_PID_RANGE: std::ops::Range<usize> = 4..16;
const SACN_ROOT_VECTOR_RANGE: std::ops::Range<usize> = 18..22;
const SACN_CID_RANGE: std::ops::Range<usize> = 22..38;
const SACN_FRAMING_VECTOR_RANGE: std::ops::Range<usize> = 40..44;
const SACN_SEQUENCE_OFFSET: usize = 111;
const SACN_UNIVERSE_RANGE: std::ops::Range<usize> = 113..115;
const SACN_DMP_VECTOR_OFFSET: usize = 117;
const SACN_DMP_PROPERTY_VALUE_COUNT_RANGE: std::ops::Range<usize> = 123..125;
const SACN_START_CODE_OFFSET: usize = 125;
const SACN_DMX_DATA_OFFSET: usize = 126;
const SACN_DMX_MAX_SLOTS: usize = 512;
const SACN_ACN_PID: &[u8; 12] = b"ASC-E1.17\0\0\0";
const SACN_PREAMBLE_SIZE: u16 = 0x0010;
const SACN_POSTAMBLE_SIZE: u16 = 0x0000;
const SACN_ROOT_VECTOR_DATA: u32 = 0x0000_0004;
const SACN_FRAMING_VECTOR_DMX: u32 = 0x0000_0002;
const SACN_DMP_VECTOR_SET_PROPERTY: u8 = 0x02;

fn main() -> Result<(), String> {
    let root = PathBuf::from("tests/golden");
    write_sacn_fixtures(&root)?;
    write_artnet_fixtures(&root)?;
    Ok(())
}

fn write_sacn_fixtures(root: &Path) -> Result<(), String> {
    write_capture(
        root.join("sacn_burst").join("input.pcapng"),
        CaptureSpec::sacn(vec![1, 2, 5, 6, 10]),
    )?;
    write_capture(
        root.join("sacn_gap").join("input.pcapng"),
        CaptureSpec::sacn(vec![1, 2, 10]),
    )?;
    Ok(())
}

fn write_artnet_fixtures(root: &Path) -> Result<(), String> {
    write_capture(
        root.join("artnet_burst").join("input.pcapng"),
        CaptureSpec::artnet(vec![1, 2, 5, 6, 10]),
    )?;
    write_capture(
        root.join("artnet_gap").join("input.pcapng"),
        CaptureSpec::artnet(vec![1, 2, 10]),
    )?;
    Ok(())
}

struct CaptureSpec {
    protocol: Protocol,
    sequences: Vec<u8>,
}

enum Protocol {
    Sacn,
    ArtNet,
}

impl CaptureSpec {
    fn sacn(sequences: Vec<u8>) -> Self {
        Self {
            protocol: Protocol::Sacn,
            sequences,
        }
    }

    fn artnet(sequences: Vec<u8>) -> Self {
        Self {
            protocol: Protocol::ArtNet,
            sequences,
        }
    }
}

fn write_capture(path: PathBuf, spec: CaptureSpec) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {}", parent.display(), err))?;
    }

    let mut packets = Vec::new();
    for (idx, seq) in spec.sequences.iter().copied().enumerate() {
        let payload = match spec.protocol {
            Protocol::Sacn => build_sacn_payload(seq, &[seq, 0x00], 1),
            Protocol::ArtNet => build_artnet_payload(seq, &[seq, 0x00], 1),
        };
        let frame = match spec.protocol {
            Protocol::Sacn => {
                build_ipv4_udp_packet("10.0.0.1", "10.0.0.2", SACN_PORT, SACN_PORT, &payload)
            }
            Protocol::ArtNet => {
                build_ipv4_udp_packet("10.0.0.1", "10.0.0.2", ARTNET_PORT, ARTNET_PORT, &payload)
            }
        };
        let ts_us = (idx as u64) * 1_000_000;
        packets.push((ts_us, frame));
    }

    write_pcapng(&path, &packets)?;
    Ok(())
}

fn build_artnet_payload(sequence: u8, slots: &[u8], universe: u16) -> Vec<u8> {
    let length = slots.len().min(ARTNET_DMX_MAX_SLOTS);
    let mut payload = vec![0u8; ARTNET_DMX_DATA_OFFSET + length];
    payload[..ARTNET_ID.len()].copy_from_slice(ARTNET_ID);
    payload[ARTNET_OP_CODE_RANGE.clone()].copy_from_slice(&ARTNET_ARTDMX_OPCODE.to_le_bytes());
    payload[ARTNET_SEQUENCE_OFFSET] = sequence;
    payload[ARTNET_UNIVERSE_RANGE.clone()].copy_from_slice(&universe.to_le_bytes());
    payload[ARTNET_LENGTH_RANGE.clone()].copy_from_slice(&(length as u16).to_be_bytes());
    payload[ARTNET_DMX_DATA_OFFSET..ARTNET_DMX_DATA_OFFSET + length]
        .copy_from_slice(&slots[..length]);
    payload
}

fn build_sacn_payload(sequence: u8, slots: &[u8], universe: u16) -> Vec<u8> {
    let length = slots.len().min(SACN_DMX_MAX_SLOTS);
    let mut payload = vec![0u8; SACN_DMX_DATA_OFFSET + length];
    payload[SACN_PREAMBLE_SIZE_RANGE.clone()].copy_from_slice(&SACN_PREAMBLE_SIZE.to_be_bytes());
    payload[SACN_POSTAMBLE_SIZE_RANGE.clone()].copy_from_slice(&SACN_POSTAMBLE_SIZE.to_be_bytes());
    payload[SACN_ACN_PID_RANGE.clone()].copy_from_slice(SACN_ACN_PID);
    payload[SACN_ROOT_VECTOR_RANGE.clone()].copy_from_slice(&SACN_ROOT_VECTOR_DATA.to_be_bytes());
    payload[SACN_CID_RANGE.clone()].copy_from_slice(&cid_bytes());
    payload[SACN_FRAMING_VECTOR_RANGE.clone()]
        .copy_from_slice(&SACN_FRAMING_VECTOR_DMX.to_be_bytes());
    payload[SACN_SEQUENCE_OFFSET] = sequence;
    payload[SACN_UNIVERSE_RANGE.clone()].copy_from_slice(&universe.to_be_bytes());
    payload[SACN_DMP_VECTOR_OFFSET] = SACN_DMP_VECTOR_SET_PROPERTY;
    let count = (length as u16) + 1;
    payload[SACN_DMP_PROPERTY_VALUE_COUNT_RANGE.clone()].copy_from_slice(&count.to_be_bytes());
    payload[SACN_START_CODE_OFFSET] = 0x00;
    payload[SACN_DMX_DATA_OFFSET..SACN_DMX_DATA_OFFSET + length].copy_from_slice(&slots[..length]);
    payload
}

fn cid_bytes() -> [u8; 16] {
    let mut cid = [0u8; 16];
    for (idx, value) in cid.iter_mut().enumerate() {
        *value = idx as u8;
    }
    cid
}

fn build_ipv4_udp_packet(
    src_ip: &str,
    dst_ip: &str,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
    packet.extend_from_slice(&[0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]);
    packet.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

    let total_len = 20u16 + 8u16 + (payload.len() as u16);
    let mut ip_header = [0u8; 20];
    ip_header[0] = 0x45;
    ip_header[2..4].copy_from_slice(&total_len.to_be_bytes());
    ip_header[8] = 64;
    ip_header[9] = UDP_PROTO;
    ip_header[12..16].copy_from_slice(&parse_ipv4(src_ip));
    ip_header[16..20].copy_from_slice(&parse_ipv4(dst_ip));
    let checksum = ipv4_checksum(&ip_header);
    ip_header[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet.extend_from_slice(&ip_header);

    let udp_len = 8u16 + (payload.len() as u16);
    packet.extend_from_slice(&src_port.to_be_bytes());
    packet.extend_from_slice(&dst_port.to_be_bytes());
    packet.extend_from_slice(&udp_len.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());

    packet.extend_from_slice(payload);
    packet
}

fn parse_ipv4(ip: &str) -> [u8; 4] {
    let mut out = [0u8; 4];
    for (idx, part) in ip.split('.').enumerate() {
        out[idx] = part.parse::<u8>().unwrap_or(0);
    }
    out
}

fn ipv4_checksum(header: &[u8; 20]) -> u16 {
    let mut sum = 0u32;
    for chunk in header.chunks(2) {
        let part = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        sum = sum.wrapping_add(part);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn write_pcapng(path: &Path, packets: &[(u64, Vec<u8>)]) -> Result<(), String> {
    let mut output = Vec::new();
    output.extend_from_slice(&pcapng_block(0x0A0D0D0A, &section_header_body()));
    output.extend_from_slice(&pcapng_block(1, &interface_desc_body()));

    for (ts_us, data) in packets {
        output.extend_from_slice(&pcapng_block(6, &enhanced_packet_body(*ts_us, data)));
    }

    fs::write(path, output)
        .map_err(|err| format!("failed to write {}: {}", path.display(), err))?;
    Ok(())
}

fn pcapng_block(block_type: u32, body: &[u8]) -> Vec<u8> {
    let total_len = (8 + body.len() + 4) as u32;
    let mut block = Vec::with_capacity(total_len as usize);
    block.extend_from_slice(&block_type.to_be_bytes());
    block.extend_from_slice(&total_len.to_be_bytes());
    block.extend_from_slice(body);
    block.extend_from_slice(&total_len.to_be_bytes());
    block
}

fn section_header_body() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0x1A2B3C4Du32.to_be_bytes());
    body.extend_from_slice(&1u16.to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(&(-1i64).to_be_bytes());
    body
}

fn interface_desc_body() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&1u16.to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(&65535u32.to_be_bytes());
    body
}

fn enhanced_packet_body(ts_us: u64, data: &[u8]) -> Vec<u8> {
    let ts_high = ((ts_us >> 32) & 0xFFFF_FFFF) as u32;
    let ts_low = (ts_us & 0xFFFF_FFFF) as u32;
    let cap_len = data.len() as u32;
    let mut body = Vec::new();
    body.extend_from_slice(&0u32.to_be_bytes());
    body.extend_from_slice(&ts_high.to_be_bytes());
    body.extend_from_slice(&ts_low.to_be_bytes());
    body.extend_from_slice(&cap_len.to_be_bytes());
    body.extend_from_slice(&cap_len.to_be_bytes());
    body.extend_from_slice(data);
    let pad_len = (4 - (data.len() % 4)) % 4;
    body.extend(std::iter::repeat(0u8).take(pad_len));
    body
}

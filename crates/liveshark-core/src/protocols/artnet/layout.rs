pub const ARTNET_ID: &[u8; 8] = b"Art-Net\0";

pub const OP_CODE_RANGE: std::ops::Range<usize> = 8..10;
pub const SEQUENCE_OFFSET: usize = 12;
pub const UNIVERSE_RANGE: std::ops::Range<usize> = 14..16;
pub const LENGTH_RANGE: std::ops::Range<usize> = 16..18;

pub const ARTDMX_OPCODE: u16 = 0x5000;

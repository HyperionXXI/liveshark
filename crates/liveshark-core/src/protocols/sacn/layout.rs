pub const PREAMBLE_SIZE_RANGE: std::ops::Range<usize> = 0..2;
pub const POSTAMBLE_SIZE_RANGE: std::ops::Range<usize> = 2..4;
pub const ACN_PID_RANGE: std::ops::Range<usize> = 4..16;

pub const ROOT_VECTOR_RANGE: std::ops::Range<usize> = 18..22;
pub const CID_RANGE: std::ops::Range<usize> = 22..38;

pub const FRAMING_VECTOR_RANGE: std::ops::Range<usize> = 40..44;
pub const SOURCE_NAME_RANGE: std::ops::Range<usize> = 44..108;
pub const SEQUENCE_OFFSET: usize = 111;
pub const UNIVERSE_RANGE: std::ops::Range<usize> = 113..115;

pub const DMP_VECTOR_OFFSET: usize = 117;
pub const DMP_PROPERTY_VALUE_COUNT_RANGE: std::ops::Range<usize> = 123..125;
pub const START_CODE_OFFSET: usize = 125;
pub const DMX_DATA_OFFSET: usize = 126;
pub const DMX_MAX_SLOTS: usize = 512;

pub const ACN_PID: &[u8; 12] = b"ASC-E1.17\0\0\0";
pub const PREAMBLE_SIZE: u16 = 0x0010;
pub const POSTAMBLE_SIZE: u16 = 0x0000;
pub const ROOT_VECTOR_DATA: u32 = 0x0000_0004;
pub const FRAMING_VECTOR_DMX: u32 = 0x0000_0002;
pub const DMP_VECTOR_SET_PROPERTY: u8 = 0x02;

pub const MIN_LEN: usize = DMP_VECTOR_OFFSET + 1;

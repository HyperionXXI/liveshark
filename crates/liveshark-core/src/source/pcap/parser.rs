use std::fs::File;
use std::path::Path;

use pcap_parser::{
    Block, LegacyPcapReader, Linktype, PcapBlockOwned, PcapNGReader, traits::PcapReaderIterator,
};

use crate::source::{PacketEvent, PacketSource, SourceError};

use super::error::PcapSourceError;
use super::layout;
use super::reader::{is_pcapng_magic, read_magic_and_rewind};

pub struct PcapFileSource {
    inner: PcapReader,
}

enum PcapReader {
    Legacy {
        reader: LegacyPcapReader<File>,
        linktype: Option<Linktype>,
    },
    Ng {
        reader: PcapNGReader<File>,
        linktypes: Vec<Linktype>,
    },
}

impl PcapFileSource {
    pub fn open(path: &Path) -> Result<Self, SourceError> {
        let file = File::open(path).map_err(SourceError::from)?;
        let inner = create_reader(file).map_err(SourceError::from)?;
        Ok(Self { inner })
    }
}

impl PacketSource for PcapFileSource {
    fn next_packet(&mut self) -> Result<Option<PacketEvent>, SourceError> {
        next_packet(&mut self.inner).map_err(SourceError::from)
    }
}

fn create_reader(file: File) -> Result<PcapReader, PcapSourceError> {
    let mut file = file;
    let magic = read_magic_and_rewind(&mut file)?;

    if is_pcapng_magic(&magic) {
        let reader = PcapNGReader::new(layout::PCAP_READER_BUFFER_SIZE, file).map_err(|e| {
            PcapSourceError::Pcap {
                context: "pcapng reader init",
                message: e.to_string(),
            }
        })?;
        Ok(PcapReader::Ng {
            reader,
            linktypes: Vec::new(),
        })
    } else {
        let reader = LegacyPcapReader::new(layout::PCAP_READER_BUFFER_SIZE, file).map_err(|e| {
            PcapSourceError::Pcap {
                context: "pcap reader init",
                message: e.to_string(),
            }
        })?;
        Ok(PcapReader::Legacy {
            reader,
            linktype: None,
        })
    }
}

fn next_packet(reader: &mut PcapReader) -> Result<Option<PacketEvent>, PcapSourceError> {
    loop {
        match reader {
            PcapReader::Legacy { reader, linktype } => match reader.next() {
                Ok((offset, block)) => {
                    let event = match block {
                        PcapBlockOwned::LegacyHeader(header) => {
                            *linktype = Some(header.network);
                            None
                        }
                        PcapBlockOwned::Legacy(packet) => {
                            let ts = packet.ts_sec as f64 + (packet.ts_usec as f64 * 1e-6);
                            let lt = linktype.unwrap_or(Linktype::ETHERNET);
                            Some(PacketEvent {
                                ts: Some(ts),
                                linktype: lt,
                                data: packet.data.to_vec(),
                            })
                        }
                        _ => None,
                    };
                    reader.consume(offset);
                    if event.is_some() {
                        return Ok(event);
                    }
                }
                Err(pcap_parser::PcapError::Eof) => return Ok(None),
                Err(pcap_parser::PcapError::Incomplete(_)) => {
                    reader.refill().map_err(|e| PcapSourceError::Pcap {
                        context: "pcap reader refill",
                        message: e.to_string(),
                    })?;
                }
                Err(e) => {
                    return Err(PcapSourceError::Pcap {
                        context: "pcap reader next",
                        message: e.to_string(),
                    });
                }
            },
            PcapReader::Ng { reader, linktypes } => match reader.next() {
                Ok((offset, block)) => {
                    let event = match block {
                        PcapBlockOwned::NG(Block::InterfaceDescription(intf)) => {
                            linktypes.push(intf.linktype);
                            None
                        }
                        PcapBlockOwned::NG(Block::EnhancedPacket(packet)) => {
                            let ts = pcapng_ts_to_seconds(packet.ts_high, packet.ts_low);
                            let lt = linktypes
                                .get(packet.if_id as usize)
                                .copied()
                                .unwrap_or(Linktype::ETHERNET);
                            Some(PacketEvent {
                                ts: Some(ts),
                                linktype: lt,
                                data: packet.data.to_vec(),
                            })
                        }
                        _ => None,
                    };
                    reader.consume(offset);
                    if event.is_some() {
                        return Ok(event);
                    }
                }
                Err(pcap_parser::PcapError::Eof) => return Ok(None),
                Err(pcap_parser::PcapError::Incomplete(_)) => {
                    reader.refill().map_err(|e| PcapSourceError::Pcap {
                        context: "pcapng reader refill",
                        message: e.to_string(),
                    })?;
                }
                Err(e) => {
                    return Err(PcapSourceError::Pcap {
                        context: "pcapng reader next",
                        message: e.to_string(),
                    });
                }
            },
        }
    }
}

fn pcapng_ts_to_seconds(ts_high: u32, ts_low: u32) -> f64 {
    let ts = ((ts_high as u64) << 32) | (ts_low as u64);
    ts as f64 * 1e-6
}

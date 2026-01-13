use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use pcap_parser::{
    Block, LegacyPcapReader, Linktype, PcapBlockOwned, PcapNGReader, traits::PcapReaderIterator,
};

use super::{PacketEvent, PacketSource, SourceError};

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
        let mut file = File::open(path)?;
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)?;
        file.seek(SeekFrom::Start(0))?;

        let inner = if magic == [0x0a, 0x0d, 0x0d, 0x0a] {
            let reader =
                PcapNGReader::new(64 * 1024, file).map_err(|e| SourceError::Pcap(e.to_string()))?;
            PcapReader::Ng {
                reader,
                linktypes: Vec::new(),
            }
        } else {
            let reader = LegacyPcapReader::new(64 * 1024, file)
                .map_err(|e| SourceError::Pcap(e.to_string()))?;
            PcapReader::Legacy {
                reader,
                linktype: None,
            }
        };

        Ok(Self { inner })
    }
}

impl PacketSource for PcapFileSource {
    fn next_packet(&mut self) -> Result<Option<PacketEvent>, SourceError> {
        loop {
            match &mut self.inner {
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
                        reader
                            .refill()
                            .map_err(|e| SourceError::Pcap(e.to_string()))?;
                    }
                    Err(e) => return Err(SourceError::Pcap(e.to_string())),
                },
                PcapReader::Ng { reader, linktypes } => match reader.next() {
                    Ok((offset, block)) => {
                        let event = match block {
                            PcapBlockOwned::NG(Block::InterfaceDescription(intf)) => {
                                linktypes.push(intf.linktype);
                                None
                            }
                            PcapBlockOwned::NG(Block::EnhancedPacket(packet)) => {
                                let ts = Some(pcapng_ts_to_seconds(packet.ts_high, packet.ts_low));
                                let lt = linktypes
                                    .get(packet.if_id as usize)
                                    .copied()
                                    .unwrap_or(Linktype::ETHERNET);
                                Some(PacketEvent {
                                    ts,
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
                        reader
                            .refill()
                            .map_err(|e| SourceError::Pcap(e.to_string()))?;
                    }
                    Err(e) => return Err(SourceError::Pcap(e.to_string())),
                },
            }
        }
    }
}

fn pcapng_ts_to_seconds(ts_high: u32, ts_low: u32) -> f64 {
    let ts = ((ts_high as u64) << 32) | (ts_low as u64);
    ts as f64 * 1e-6
}

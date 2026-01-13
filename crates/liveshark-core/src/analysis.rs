use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap_parser::Linktype;
use thiserror::Error;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::{make_stub_report, CaptureSummary, FlowSummary, Report};
use crate::source::{PacketEvent, PacketSource, PcapFileSource, SourceError};

#[derive(Debug, Error)]
pub enum AnalysisError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Source error: {0}")]
    Source(#[from] SourceError),
}

#[derive(Debug, Hash, PartialEq, Eq)]
struct FlowKey {
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
}

#[derive(Debug, Default, Clone)]
struct FlowStats {
    packets: u64,
    bytes: u64,
}

pub fn analyze_pcap_file(path: &Path) -> Result<Report, AnalysisError> {
    let source = PcapFileSource::open(path)?;
    analyze_source(path, source)
}

fn analyze_source<S: PacketSource>(path: &Path, mut source: S) -> Result<Report, AnalysisError> {
    let mut packets_total = 0u64;
    let mut first_ts = None;
    let mut last_ts = None;
    let mut flow_stats: HashMap<FlowKey, FlowStats> = HashMap::new();

    while let Some(PacketEvent { ts, linktype, data }) = source.next_packet()? {
        packets_total += 1;
        update_ts_bounds(&mut first_ts, &mut last_ts, ts);
        if let Some(flow_key) = parse_udp_flow(linktype, &data) {
            let entry = flow_stats.entry(flow_key).or_default();
            entry.packets += 1;
            entry.bytes += data.len() as u64;
        }
    }

    let mut report = make_stub_report(&path.display().to_string(), path.metadata()?.len());
    report.capture_summary = Some(CaptureSummary {
        packets_total,
        time_start: ts_to_rfc3339(first_ts),
        time_end: ts_to_rfc3339(last_ts),
    });

    let duration_s = match (first_ts, last_ts) {
        (Some(start), Some(end)) if end > start => Some(end - start),
        _ => None,
    };

    let mut flows: Vec<FlowSummary> = flow_stats
        .into_iter()
        .map(|(key, stats)| {
            let (pps, bps) = duration_s
                .map(|d| (stats.packets as f64 / d, stats.bytes as f64 / d))
                .map(|(pps, bps)| (Some(pps), Some(bps)))
                .unwrap_or((None, None));

            FlowSummary {
                app_proto: "udp".to_string(),
                src: format_endpoint(key.src_ip, key.src_port),
                dst: format_endpoint(key.dst_ip, key.dst_port),
                pps,
                bps,
                iat_jitter_ms: None,
            }
        })
        .collect();

    flows.sort_by(|a, b| a.src.cmp(&b.src).then_with(|| a.dst.cmp(&b.dst)));
    report.flows = flows;
    Ok(report)
}

fn parse_udp_flow(linktype: Linktype, data: &[u8]) -> Option<FlowKey> {
    let sliced = match linktype {
        Linktype::ETHERNET => SlicedPacket::from_ethernet(data).ok()?,
        Linktype::RAW => SlicedPacket::from_ip(data).ok()?,
        _ => return None,
    };

    let net = sliced.net?;
    let transport = sliced.transport?;
    let udp = match transport {
        TransportSlice::Udp(udp) => udp,
        _ => return None,
    };

    let (src_ip, dst_ip) = match net {
        NetSlice::Ipv4(ipv4) => (
            IpAddr::V4(ipv4.header().source_addr()),
            IpAddr::V4(ipv4.header().destination_addr()),
        ),
        NetSlice::Ipv6(ipv6) => (
            IpAddr::V6(ipv6.header().source_addr()),
            IpAddr::V6(ipv6.header().destination_addr()),
        ),
    };

    Some(FlowKey {
        src_ip,
        src_port: udp.source_port(),
        dst_ip,
        dst_port: udp.destination_port(),
    })
}

fn format_endpoint(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(addr) => format!("{}:{}", addr, port),
        IpAddr::V6(addr) => format!("[{}]:{}", addr, port),
    }
}

fn update_ts_bounds(first: &mut Option<f64>, last: &mut Option<f64>, ts: Option<f64>) {
    let ts = match ts {
        Some(ts) => ts,
        None => return,
    };
    match first {
        None => *first = Some(ts),
        Some(existing) => {
            if ts < *existing {
                *first = Some(ts);
            }
        }
    }
    match last {
        None => *last = Some(ts),
        Some(existing) => {
            if ts > *existing {
                *last = Some(ts);
            }
        }
    }
}

fn ts_to_rfc3339(ts: Option<f64>) -> Option<String> {
    let ts = ts?;
    let nanos = (ts * 1_000_000_000.0) as i128;
    OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .ok()
        .and_then(|dt| dt.format(&Rfc3339).ok())
}

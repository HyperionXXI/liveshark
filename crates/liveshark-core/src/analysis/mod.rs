use std::collections::HashMap;
use std::path::Path;

use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::source::{PacketEvent, PacketSource, PcapFileSource, SourceError};
use crate::{CaptureSummary, DEFAULT_GENERATED_AT, Report, make_stub_report};

mod dmx;
mod flows;
mod udp;
mod universes;

use dmx::{DmxFrame, DmxProtocol, DmxStore};
use flows::{FlowKey, FlowStats, add_flow_stats, build_flow_summaries};
use udp::parse_udp_packet;
use universes::{
    UniverseStats, add_artnet_frame, add_sacn_frame, build_artnet_universe_summaries,
    build_conflicts, build_sacn_universe_summaries,
};

use crate::protocols::artnet::parse_artdmx;
use crate::protocols::sacn::parse_sacn_dmx;

#[derive(Debug, Error)]
pub enum AnalysisError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Source error: {0}")]
    Source(#[from] SourceError),
}

pub fn analyze_pcap_file(path: &Path) -> Result<Report, AnalysisError> {
    let source = PcapFileSource::open(path)?;
    analyze_source(path, source)
}

pub fn analyze_source<S: PacketSource>(
    path: &Path,
    mut source: S,
) -> Result<Report, AnalysisError> {
    let mut packets_total = 0u64;
    let mut first_ts = None;
    let mut last_ts = None;
    let mut flow_stats: HashMap<FlowKey, FlowStats> = HashMap::new();
    let mut artnet_stats: HashMap<u16, UniverseStats> = HashMap::new();
    let mut sacn_stats: HashMap<u16, UniverseStats> = HashMap::new();
    let mut dmx_store = DmxStore::new();

    while let Some(PacketEvent { ts, linktype, data }) = source.next_packet()? {
        packets_total += 1;
        update_ts_bounds(&mut first_ts, &mut last_ts, ts);
        if let Ok(Some(udp)) = parse_udp_packet(linktype, &data) {
            if let Ok(Some(art)) = parse_artdmx(udp.payload) {
                let source_id = add_artnet_frame(
                    &mut artnet_stats,
                    art.universe,
                    &udp.src_ip,
                    udp.src_port,
                    art.sequence,
                    ts,
                );
                dmx_store.push(DmxFrame {
                    universe: art.universe,
                    timestamp: ts,
                    source_id,
                    protocol: DmxProtocol::ArtNet,
                    slots: art.slots,
                });
            }
            if let Ok(Some(sacn)) = parse_sacn_dmx(udp.payload) {
                let source_id = add_sacn_frame(
                    &mut sacn_stats,
                    sacn.universe,
                    &udp.src_ip,
                    udp.src_port,
                    sacn.cid,
                    sacn.source_name,
                    sacn.sequence,
                    ts,
                );
                dmx_store.push(DmxFrame {
                    universe: sacn.universe,
                    timestamp: ts,
                    source_id,
                    protocol: DmxProtocol::Sacn,
                    slots: sacn.slots,
                });
            }
            add_flow_stats(&mut flow_stats, &udp);
        }
    }

    let mut report = make_stub_report(&path.display().to_string(), path.metadata()?.len());
    report.capture_summary = Some(CaptureSummary {
        packets_total,
        time_start: ts_to_rfc3339(first_ts),
        time_end: ts_to_rfc3339(last_ts),
    });
    report.generated_at = report
        .capture_summary
        .as_ref()
        .and_then(|summary| summary.time_end.clone().or(summary.time_start.clone()))
        .unwrap_or_else(|| DEFAULT_GENERATED_AT.to_string());

    let duration_s = match (first_ts, last_ts) {
        (Some(start), Some(end)) if end > start => Some(end - start),
        _ => None,
    };

    let mut conflicts = build_conflicts(&artnet_stats);
    conflicts.extend(build_conflicts(&sacn_stats));
    report.conflicts = conflicts;
    report.flows = build_flow_summaries(flow_stats, duration_s);
    report.universes = {
        let mut universes = build_artnet_universe_summaries(artnet_stats);
        universes.extend(build_sacn_universe_summaries(sacn_stats));
        universes.sort_by(|a, b| {
            a.universe
                .cmp(&b.universe)
                .then_with(|| a.proto.cmp(&b.proto))
        });
        universes
    };
    Ok(report)
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

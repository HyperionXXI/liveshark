use std::collections::HashMap;
use std::path::Path;

use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::source::{PacketEvent, PacketSource, PcapFileSource, SourceError};
use crate::{
    CaptureSummary, ComplianceSummary, DEFAULT_GENERATED_AT, Report, Violation, make_stub_report,
};

mod dmx;
mod flows;
mod udp;
mod universes;

use dmx::{DmxFrame, DmxProtocol, DmxStateStore, DmxStore};
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
    let mut dmx_state = DmxStateStore::new();
    let mut compliance: HashMap<String, ComplianceSummary> = HashMap::new();

    while let Some(PacketEvent { ts, linktype, data }) = source.next_packet()? {
        packets_total += 1;
        update_ts_bounds(&mut first_ts, &mut last_ts, ts);
        if let Ok(Some(udp)) = parse_udp_packet(linktype, &data) {
            match parse_artdmx(udp.payload) {
                Ok(Some(art)) => {
                    let source_id = add_artnet_frame(
                        &mut artnet_stats,
                        art.universe,
                        &udp.src_ip,
                        udp.src_port,
                        art.sequence,
                        ts,
                    );
                    let slots = dmx_state.apply_partial(
                        art.universe,
                        source_id.clone(),
                        DmxProtocol::ArtNet,
                        &art.slots,
                    );
                    dmx_store.push(DmxFrame {
                        universe: art.universe,
                        timestamp: ts,
                        source_id,
                        protocol: DmxProtocol::ArtNet,
                        slots,
                    });
                }
                Ok(None) => {}
                Err(err) => match err {
                    crate::protocols::artnet::error::ArtNetError::InvalidUniverseId { value } => {
                        record_violation(
                            &mut compliance,
                            "artnet",
                            "LS-ARTNET-UNIVERSE-ID",
                            "error",
                            "Invalid Art-Net universe id; packet ignored",
                            format!("value={}", value),
                        );
                    }
                    crate::protocols::artnet::error::ArtNetError::InvalidLength { length } => {
                        record_violation(
                            &mut compliance,
                            "artnet",
                            "LS-ARTNET-LENGTH",
                            "error",
                            "Invalid ArtDMX length; packet ignored",
                            format!("length={}", length),
                        );
                    }
                    crate::protocols::artnet::error::ArtNetError::TooShort { needed, actual } => {
                        record_violation(
                            &mut compliance,
                            "artnet",
                            "LS-ARTNET-TOO-SHORT",
                            "error",
                            "Art-Net payload too short; packet ignored",
                            format!("needed={}, actual={}", needed, actual),
                        );
                    }
                },
            }
            match parse_sacn_dmx(udp.payload) {
                Ok(Some(sacn)) => {
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
                    let slots = dmx_state.apply_partial(
                        sacn.universe,
                        source_id.clone(),
                        DmxProtocol::Sacn,
                        &sacn.slots,
                    );
                    dmx_store.push(DmxFrame {
                        universe: sacn.universe,
                        timestamp: ts,
                        source_id,
                        protocol: DmxProtocol::Sacn,
                        slots,
                    });
                }
                Ok(None) => {}
                Err(err) => match err {
                    crate::protocols::sacn::error::SacnError::InvalidStartCode { value } => {
                        record_violation(
                            &mut compliance,
                            "sacn",
                            "LS-SACN-START-CODE",
                            "error",
                            "Invalid sACN start code; packet ignored",
                            format!("value={}", value),
                        );
                    }
                    crate::protocols::sacn::error::SacnError::InvalidPropertyValueCount {
                        count,
                    } => {
                        record_violation(
                            &mut compliance,
                            "sacn",
                            "LS-SACN-PROPERTY-COUNT",
                            "error",
                            "Invalid sACN property value count; packet ignored",
                            format!("count={}", count),
                        );
                    }
                    crate::protocols::sacn::error::SacnError::InvalidDmxLength { length } => {
                        record_violation(
                            &mut compliance,
                            "sacn",
                            "LS-SACN-DMX-LENGTH",
                            "error",
                            "Invalid sACN DMX data length; packet ignored",
                            format!("length={}", length),
                        );
                    }
                    crate::protocols::sacn::error::SacnError::TooShort { needed, actual } => {
                        record_violation(
                            &mut compliance,
                            "sacn",
                            "LS-SACN-TOO-SHORT",
                            "error",
                            "sACN payload too short; packet ignored",
                            format!("needed={}, actual={}", needed, actual),
                        );
                    }
                },
            }
            add_flow_stats(&mut flow_stats, &udp, ts);
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

    let mut conflicts = build_conflicts(&artnet_stats, &dmx_store);
    conflicts.extend(build_conflicts(&sacn_stats, &dmx_store));
    report.conflicts = conflicts;
    report.flows = build_flow_summaries(flow_stats, duration_s);
    report.universes = {
        let mut universes = build_artnet_universe_summaries(artnet_stats, &dmx_store);
        universes.extend(build_sacn_universe_summaries(sacn_stats, &dmx_store));
        universes.sort_by(|a, b| {
            a.universe
                .cmp(&b.universe)
                .then_with(|| a.proto.cmp(&b.proto))
        });
        universes
    };
    if !compliance.is_empty() {
        let mut entries: Vec<ComplianceSummary> = compliance.into_values().collect();
        entries.sort_by(|a, b| a.protocol.cmp(&b.protocol));
        report.compliance = entries;
    }
    Ok(report)
}

fn record_violation(
    compliance: &mut HashMap<String, ComplianceSummary>,
    protocol: &str,
    id: &str,
    severity: &str,
    message: &str,
    example: String,
) {
    let entry = compliance
        .entry(protocol.to_string())
        .or_insert_with(|| ComplianceSummary {
            protocol: protocol.to_string(),
            compliance_percentage: 100.0,
            violations: Vec::new(),
        });

    if let Some(existing) = entry.violations.iter_mut().find(|v| v.id == id) {
        existing.count += 1;
        if existing.examples.len() < 3 {
            existing.examples.push(example);
        }
        return;
    }

    entry.violations.push(Violation {
        id: id.to_string(),
        severity: severity.to_string(),
        message: message.to_string(),
        count: 1,
        examples: vec![example],
    });
}

#[cfg(test)]
mod tests {
    use super::{ComplianceSummary, record_violation};
    use std::collections::HashMap;

    #[test]
    fn compliance_aggregates_by_protocol_and_id() {
        let mut compliance: HashMap<String, ComplianceSummary> = HashMap::new();

        record_violation(
            &mut compliance,
            "artnet",
            "LS-ARTNET-UNIVERSE-ID",
            "error",
            "Invalid Art-Net universe id; packet ignored",
            "value=32768".to_string(),
        );
        record_violation(
            &mut compliance,
            "artnet",
            "LS-ARTNET-UNIVERSE-ID",
            "error",
            "Invalid Art-Net universe id; packet ignored",
            "value=40000".to_string(),
        );
        record_violation(
            &mut compliance,
            "sacn",
            "LS-SACN-START-CODE",
            "error",
            "Invalid sACN start code; packet ignored",
            "value=1".to_string(),
        );

        let artnet = compliance.get("artnet").expect("artnet compliance");
        assert_eq!(artnet.violations.len(), 1);
        let violation = &artnet.violations[0];
        assert_eq!(violation.count, 2);
        assert_eq!(violation.examples.len(), 2);

        let sacn = compliance.get("sacn").expect("sacn compliance");
        assert_eq!(sacn.violations.len(), 1);
        assert_eq!(sacn.violations[0].count, 1);
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

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::source::{PacketEvent, PacketSource, PcapFileSource, SourceError};
use crate::{
    CaptureSummary, ComplianceSummary, DEFAULT_GENERATED_AT, Report, Violation, make_stub_report,
};

const ARTNET_PORT: u16 = 6454;
const SACN_PORT: u16 = 5568;

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
        match parse_udp_packet(linktype, &data) {
            Ok(Some(udp)) => {
                match parse_artdmx(udp.payload) {
                    Ok(Some(art)) => {
                        if udp.src_port != ARTNET_PORT && udp.dst_port != ARTNET_PORT {
                            record_violation(
                                &mut compliance,
                                "artnet",
                                "LS-ARTNET-PORT",
                                "warning",
                                "Non-standard Art-Net port; packet accepted",
                                format_violation_example(
                                    format!(
                                        "ports={}:{}->{}:{}",
                                        udp.src_ip, udp.src_port, udp.dst_ip, udp.dst_port
                                    ),
                                    Some((&udp.src_ip, udp.src_port)),
                                    ts,
                                ),
                            );
                        }
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
                        crate::protocols::artnet::error::ArtNetError::InvalidUniverseId {
                            value,
                        } => {
                            record_violation(
                                &mut compliance,
                                "artnet",
                                "LS-ARTNET-UNIVERSE-ID",
                                "error",
                                "Invalid Art-Net universe id; packet ignored",
                                format_violation_example(
                                    format!("value={}", value),
                                    Some((&udp.src_ip, udp.src_port)),
                                    ts,
                                ),
                            );
                        }
                        crate::protocols::artnet::error::ArtNetError::InvalidLength { length } => {
                            record_violation(
                                &mut compliance,
                                "artnet",
                                "LS-ARTNET-LENGTH",
                                "error",
                                "Invalid ArtDMX length; packet ignored",
                                format_violation_example(
                                    format!("length={}", length),
                                    Some((&udp.src_ip, udp.src_port)),
                                    ts,
                                ),
                            );
                        }
                        crate::protocols::artnet::error::ArtNetError::TooShort {
                            needed,
                            actual,
                        } => {
                            record_violation(
                                &mut compliance,
                                "artnet",
                                "LS-ARTNET-TOO-SHORT",
                                "error",
                                "Invalid Art-Net payload length; packet ignored",
                                format_violation_example(
                                    format!("needed={}, actual={}", needed, actual),
                                    Some((&udp.src_ip, udp.src_port)),
                                    ts,
                                ),
                            );
                        }
                        crate::protocols::artnet::error::ArtNetError::UnsupportedOpCode {
                            opcode,
                        } => {
                            record_violation(
                                &mut compliance,
                                "artnet",
                                "LS-ARTNET-OPCODE",
                                "error",
                                "Unsupported Art-Net opcode; packet ignored",
                                format_violation_example(
                                    format!("opcode=0x{:04x}", opcode),
                                    Some((&udp.src_ip, udp.src_port)),
                                    ts,
                                ),
                            );
                        }
                    },
                }
                match parse_sacn_dmx(udp.payload) {
                    Ok(Some(sacn)) => {
                        if udp.src_port != SACN_PORT && udp.dst_port != SACN_PORT {
                            record_violation(
                                &mut compliance,
                                "sacn",
                                "LS-SACN-PORT",
                                "warning",
                                "Non-standard sACN port; packet accepted",
                                format_violation_example(
                                    format!(
                                        "ports={}:{}->{}:{}",
                                        udp.src_ip, udp.src_port, udp.dst_ip, udp.dst_port
                                    ),
                                    Some((&udp.src_ip, udp.src_port)),
                                    ts,
                                ),
                            );
                        }
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
                                format_violation_example(
                                    format!("value={}", value),
                                    Some((&udp.src_ip, udp.src_port)),
                                    ts,
                                ),
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
                                format_violation_example(
                                    format!("count={}", count),
                                    Some((&udp.src_ip, udp.src_port)),
                                    ts,
                                ),
                            );
                        }
                        crate::protocols::sacn::error::SacnError::InvalidDmxLength { length } => {
                            record_violation(
                                &mut compliance,
                                "sacn",
                                "LS-SACN-DMX-LENGTH",
                                "error",
                                "Invalid sACN DMX data length; packet ignored",
                                format_violation_example(
                                    format!("length={}", length),
                                    Some((&udp.src_ip, udp.src_port)),
                                    ts,
                                ),
                            );
                        }
                        crate::protocols::sacn::error::SacnError::TooShort { needed, actual } => {
                            record_violation(
                                &mut compliance,
                                "sacn",
                                "LS-SACN-TOO-SHORT",
                                "error",
                                "Invalid sACN payload length; packet ignored",
                                format_violation_example(
                                    format!("needed={}, actual={}", needed, actual),
                                    Some((&udp.src_ip, udp.src_port)),
                                    ts,
                                ),
                            );
                        }
                        crate::protocols::sacn::error::SacnError::InvalidAcnPid => {
                            record_violation(
                                &mut compliance,
                                "sacn",
                                "LS-SACN-ACN-PID",
                                "error",
                                "Invalid sACN ACN PID; packet ignored",
                                format_violation_example(
                                    "acn_pid=invalid".to_string(),
                                    Some((&udp.src_ip, udp.src_port)),
                                    ts,
                                ),
                            );
                        }
                        crate::protocols::sacn::error::SacnError::InvalidRootVector { value } => {
                            record_violation(
                                &mut compliance,
                                "sacn",
                                "LS-SACN-ROOT-VECTOR",
                                "error",
                                "Invalid sACN root vector; packet ignored",
                                format_violation_example(
                                    format!("value=0x{:08x}", value),
                                    Some((&udp.src_ip, udp.src_port)),
                                    ts,
                                ),
                            );
                        }
                        crate::protocols::sacn::error::SacnError::InvalidFramingVector {
                            value,
                        } => {
                            record_violation(
                                &mut compliance,
                                "sacn",
                                "LS-SACN-FRAMING-VECTOR",
                                "error",
                                "Invalid sACN framing vector; packet ignored",
                                format_violation_example(
                                    format!("value=0x{:08x}", value),
                                    Some((&udp.src_ip, udp.src_port)),
                                    ts,
                                ),
                            );
                        }
                        crate::protocols::sacn::error::SacnError::InvalidDmpVector { value } => {
                            record_violation(
                                &mut compliance,
                                "sacn",
                                "LS-SACN-DMP-VECTOR",
                                "error",
                                "Invalid sACN DMP vector; packet ignored",
                                format_violation_example(
                                    format!("value=0x{:02x}", value),
                                    Some((&udp.src_ip, udp.src_port)),
                                    ts,
                                ),
                            );
                        }
                    },
                }
                add_flow_stats(&mut flow_stats, &udp, ts);
            }
            Ok(None) => {}
            Err(err) => match err {
                crate::analysis::udp::error::UdpError::Slice(message) => record_violation(
                    &mut compliance,
                    "udp",
                    "LS-UDP-SLICE",
                    "error",
                    "Invalid UDP slice; packet ignored",
                    message,
                ),
                crate::analysis::udp::error::UdpError::MissingNetworkLayer => record_violation(
                    &mut compliance,
                    "udp",
                    "LS-UDP-MISSING-NETWORK",
                    "warning",
                    "Invalid UDP packet: missing network layer; packet ignored",
                    "missing network layer".to_string(),
                ),
                crate::analysis::udp::error::UdpError::MissingIpPayload => record_violation(
                    &mut compliance,
                    "udp",
                    "LS-UDP-MISSING-PAYLOAD",
                    "warning",
                    "Invalid UDP packet: missing IP payload; packet ignored",
                    "missing IP payload".to_string(),
                ),
                crate::analysis::udp::error::UdpError::TooShort { needed, actual } => {
                    record_violation(
                        &mut compliance,
                        "udp",
                        "LS-UDP-TOO-SHORT",
                        "error",
                        "Invalid UDP payload length; packet ignored",
                        format!("needed={}, actual={}", needed, actual),
                    )
                }
            },
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
    report.compliance = finalize_compliance(compliance);
    Ok(report)
}

fn finalize_compliance(compliance: HashMap<String, ComplianceSummary>) -> Vec<ComplianceSummary> {
    if compliance.is_empty() {
        return Vec::new();
    }
    let mut entries: Vec<ComplianceSummary> = compliance.into_values().collect();
    for entry in &mut entries {
        entry.violations.sort_by(|a, b| {
            severity_rank(&a.severity)
                .cmp(&severity_rank(&b.severity))
                .then_with(|| a.id.cmp(&b.id))
        });
        for violation in &mut entry.violations {
            violation.examples.sort();
        }
    }
    entries.sort_by(|a, b| a.protocol.cmp(&b.protocol));
    entries
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "error" => 0,
        "warning" => 1,
        _ => 2,
    }
}

fn record_violation(
    compliance: &mut HashMap<String, ComplianceSummary>,
    protocol: &str,
    id: &str,
    severity: &str,
    message: &str,
    example: String,
) {
    let protocol = protocol.trim().to_ascii_lowercase();
    let id = id.trim();
    let severity = severity.trim();
    let message = message.trim();
    let example = normalize_example(example.trim());
    let protocol_key = protocol.clone();
    let entry = compliance
        .entry(protocol_key)
        .or_insert_with(|| ComplianceSummary {
            protocol: protocol.clone(),
            compliance_percentage: 100.0,
            violations: Vec::new(),
        });

    if let Some(existing) = entry.violations.iter_mut().find(|v| v.id == id) {
        existing.count += 1;
        if existing.examples.len() < 3 && !existing.examples.contains(&example) {
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

fn format_violation_example(
    base: String,
    source: Option<(&IpAddr, u16)>,
    ts: Option<f64>,
) -> String {
    let base = base.trim().to_string();
    let Some((ip, port)) = source else {
        return base;
    };
    let ts = ts_to_rfc3339(ts).unwrap_or_else(|| "unknown".to_string());
    if base.is_empty() {
        format!("source {}:{} @ {}", ip, port, ts)
    } else {
        format!("source {}:{} @ {}; {}", ip, port, ts, base)
    }
}

fn normalize_example(example: &str) -> String {
    if example.is_empty() {
        return "source unknown @ unknown".to_string();
    }
    if example.starts_with("source ") {
        return example.to_string();
    }
    format!("source unknown @ unknown; {}", example)
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

#[cfg(test)]
mod tests {
    use super::{ComplianceSummary, finalize_compliance, record_violation};
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

    #[test]
    fn compliance_examples_are_deduplicated_and_capped() {
        let mut compliance: HashMap<String, ComplianceSummary> = HashMap::new();

        record_violation(
            &mut compliance,
            "udp",
            "LS-UDP-SLICE",
            "error",
            "Invalid UDP slice; packet ignored",
            "slice-c".to_string(),
        );
        record_violation(
            &mut compliance,
            "udp",
            "LS-UDP-SLICE",
            "error",
            "Invalid UDP slice; packet ignored",
            "slice-a".to_string(),
        );
        record_violation(
            &mut compliance,
            "udp",
            "LS-UDP-SLICE",
            "error",
            "Invalid UDP slice; packet ignored",
            "slice-b".to_string(),
        );
        record_violation(
            &mut compliance,
            "udp",
            "LS-UDP-SLICE",
            "error",
            "Invalid UDP slice; packet ignored",
            "slice-a".to_string(),
        );
        record_violation(
            &mut compliance,
            "udp",
            "LS-UDP-SLICE",
            "error",
            "Invalid UDP slice; packet ignored",
            "slice-d".to_string(),
        );

        let entries = finalize_compliance(compliance);
        let udp = &entries[0];
        let violation = &udp.violations[0];
        assert_eq!(violation.count, 5);
        assert_eq!(violation.examples.len(), 3);
        assert_eq!(
            violation.examples,
            vec![
                "source unknown @ unknown; slice-a".to_string(),
                "source unknown @ unknown; slice-b".to_string(),
                "source unknown @ unknown; slice-c".to_string()
            ]
        );
    }

    #[test]
    fn compliance_entries_are_sorted_by_protocol_and_id() {
        let mut compliance: HashMap<String, ComplianceSummary> = HashMap::new();

        record_violation(
            &mut compliance,
            "sacn",
            "LS-SACN-START-CODE",
            "error",
            "Invalid sACN start code; packet ignored",
            "value=1".to_string(),
        );
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
            "LS-ARTNET-LENGTH",
            "error",
            "Invalid ArtDMX length; packet ignored",
            "length=0".to_string(),
        );

        let entries = finalize_compliance(compliance);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].protocol, "artnet");
        assert_eq!(entries[1].protocol, "sacn");
        assert_eq!(entries[0].violations.len(), 2);
        assert_eq!(entries[0].violations[0].id, "LS-ARTNET-LENGTH");
        assert_eq!(entries[0].violations[1].id, "LS-ARTNET-UNIVERSE-ID");
    }
}

//! LiveShark core library for post-mortem PCAP analysis.
//!
//! This crate implements the offline analysis pipeline used by the CLI:
//! packet sources feed the analysis layer, which drives protocol decoders
//! (layout/reader/parser) and aggregates results into a deterministic report.
//! Parsing is byte-oriented and side-effect free; all I/O is isolated in
//! `source` modules. Protocol conventions are captured in readers so parsers
//! stay minimal and consistent with the spec.
//!
//! Invariants:
//! - Report outputs are deterministic and stable across runs.
//! - DMX frames are reconstructed statefully per universe/source/protocol.
//! - Sliding-window metrics use a single, explicit inclusion rule.
//!
//! References (normative):
//! - `docs/RUST_ARCHITECTURE.md`
//! - `spec/en/LiveShark_Spec.tex`
//!
//! Version française (résumé):
//! Cette crate fournit le cœur d'analyse hors ligne : sources -> analyse ->
//! décodeurs de protocoles (layout/reader/parser) -> rapport déterministe.
//! Les E/S restent dans `source`, les conventions de protocole dans les `reader`.
//! Garanties : ordre stable du rapport, reconstruction DMX avec état, fenêtres
//! glissantes définies de manière unique. Voir la spec EN pour la référence.
//!
//! # Examples
//! ```no_run
//! use std::path::Path;
//!
//! use liveshark_core::analyze_pcap_file;
//!
//! let report = analyze_pcap_file(Path::new("capture.pcapng"))?;
//! println!("report version: {}", report.report_version);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use serde::{Deserialize, Serialize};

mod analysis;
mod protocols;
mod source;

pub use analysis::{AnalysisError, analyze_pcap_file, analyze_source};
pub use source::{PacketEvent, PacketSource, PcapFileSource, SourceError};

/// Current report schema version.
pub const REPORT_VERSION: u32 = 1;
/// Default timestamp used when no capture time is available.
pub const DEFAULT_GENERATED_AT: &str = "1970-01-01T00:00:00Z";

/// Aggregated analysis report with deterministic ordering.
///
/// # Examples
/// ```
/// use liveshark_core::make_stub_report;
///
/// let report = make_stub_report("capture.pcapng", 123);
/// assert_eq!(report.report_version, liveshark_core::REPORT_VERSION);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// Report schema version (not the binary version).
    pub report_version: u32,
    /// Tool identification metadata.
    pub tool: ToolInfo,
    /// RFC3339 timestamp representing the report generation time.
    pub generated_at: String,

    /// Input capture metadata.
    pub input: InputInfo,

    /// Optional capture summary (may be empty when unavailable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_summary: Option<CaptureSummary>,
    /// Per-universe summaries in stable order.
    pub universes: Vec<UniverseSummary>,
    /// Flow summaries in stable order.
    pub flows: Vec<FlowSummary>,
    /// Conflict summaries in stable order.
    pub conflicts: Vec<ConflictSummary>,
    /// Protocol compliance summaries in stable order.
    pub compliance: Vec<ComplianceSummary>,
}

/// Tool metadata embedded in reports.
///
/// # Examples
/// ```
/// use liveshark_core::ToolInfo;
///
/// let tool = ToolInfo {
///     name: "liveshark".to_string(),
///     version: "0.1.0".to_string(),
/// };
/// assert_eq!(tool.name, "liveshark");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    /// Tool name (e.g., "liveshark").
    pub name: String,
    /// Tool version (semver).
    pub version: String,
}

/// Input capture metadata embedded in reports.
///
/// # Examples
/// ```
/// use liveshark_core::InputInfo;
///
/// let input = InputInfo {
///     path: "capture.pcapng".to_string(),
///     bytes: 1024,
/// };
/// assert_eq!(input.bytes, 1024);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputInfo {
    /// Input path as provided to the analyzer.
    pub path: String,
    /// Input size in bytes.
    pub bytes: u64,
}

/// Basic capture summary (timestamps may be absent).
///
/// # Examples
/// ```
/// use liveshark_core::CaptureSummary;
///
/// let summary = CaptureSummary {
///     packets_total: 10,
///     time_start: None,
///     time_end: None,
/// };
/// assert_eq!(summary.packets_total, 10);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureSummary {
    /// Total packet count observed in the capture.
    pub packets_total: u64,
    /// RFC3339 timestamp of the first packet (if known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_start: Option<String>,
    /// RFC3339 timestamp of the last packet (if known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_end: Option<String>,
}

/// Per-universe metrics summary.
///
/// # Examples
/// ```
/// use liveshark_core::UniverseSummary;
///
/// let summary = UniverseSummary {
///     universe: 1,
///     proto: "artnet".to_string(),
///     sources: Vec::new(),
///     fps: None,
///     frames_count: 0,
///     loss_packets: None,
///     loss_rate: None,
///     burst_count: None,
///     max_burst_len: None,
///     jitter_ms: None,
///     dup_packets: None,
///     reordered_packets: None,
/// };
/// assert_eq!(summary.universe, 1);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniverseSummary {
    /// Canonical universe identifier (u16).
    pub universe: u16,
    /// Protocol name (e.g., "artnet", "sacn").
    pub proto: String,
    /// Observed sources for this universe (stable order).
    pub sources: Vec<SourceSummary>,
    /// Frames-per-second metric (windowed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fps: Option<f64>,
    /// Number of reconstructed frames.
    pub frames_count: u64,
    /// Observed loss packets, when sequence tracking is available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loss_packets: Option<u64>,
    /// Observed loss rate, when sequence tracking is available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loss_rate: Option<f64>,
    /// Number of bursts detected within the window.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub burst_count: Option<u64>,
    /// Maximum burst length observed within the window.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_burst_len: Option<u64>,
    /// Inter-arrival jitter in milliseconds, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jitter_ms: Option<f64>,
    /// Duplicate sACN packets observed (sequence tracked only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dup_packets: Option<u64>,
    /// Reordered sACN packets observed (sequence tracked only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reordered_packets: Option<u64>,
}

/// Source metadata for a universe.
///
/// # Examples
/// ```
/// use liveshark_core::SourceSummary;
///
/// let source = SourceSummary {
///     source_ip: "192.168.0.2".to_string(),
///     cid: None,
///     source_name: None,
/// };
/// assert_eq!(source.source_ip, "192.168.0.2");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceSummary {
    /// Source IP address as a string.
    pub source_ip: String,
    /// sACN CID in canonical form, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cid: Option<String>,
    /// sACN source name, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_name: Option<String>,
}

/// Flow-level summary for a UDP endpoint pair.
///
/// # Examples
/// ```
/// use liveshark_core::FlowSummary;
///
/// let flow = FlowSummary {
///     app_proto: "udp".to_string(),
///     src: "192.168.0.1:6454".to_string(),
///     dst: "192.168.0.2:6454".to_string(),
///     pps: None,
///     bps: None,
///     iat_jitter_ms: None,
///     max_iat_ms: None,
///     pps_peak_1s: None,
///     bps_peak_1s: None,
/// };
/// assert_eq!(flow.app_proto, "udp");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowSummary {
    /// Application protocol name (e.g., "udp").
    pub app_proto: String,
    /// Source endpoint in `ip:port` form.
    pub src: String,
    /// Destination endpoint in `ip:port` form.
    pub dst: String,
    /// Packets per second (flow active interval average).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pps: Option<f64>,
    /// Bytes per second (flow active interval average).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bps: Option<f64>,
    /// Inter-arrival jitter in milliseconds (windowed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat_jitter_ms: Option<f64>,
    /// Maximum inter-arrival time in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_iat_ms: Option<u64>,
    /// Peak packets per second over a 1s window.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pps_peak_1s: Option<u64>,
    /// Peak bytes per second over a 1s window.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bps_peak_1s: Option<u64>,
}

/// Conflict summary between multiple sources on the same universe.
///
/// # Examples
/// ```
/// use liveshark_core::ConflictSummary;
///
/// let conflict = ConflictSummary {
///     universe: 1,
///     sources: vec!["sacn:cid:deadbeef".to_string()],
///     overlap_duration_s: 1.2,
///     affected_channels: Vec::new(),
///     severity: "low".to_string(),
///     conflict_score: 1.2,
/// };
/// assert_eq!(conflict.universe, 1);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictSummary {
    /// Universe identifier for the conflict.
    pub universe: u16,
    /// Canonical source identifiers.
    pub sources: Vec<String>,
    /// Duration of the overlap in seconds.
    pub overlap_duration_s: f64,
    /// Channel indices affected (empty in v0.1).
    pub affected_channels: Vec<u16>,
    /// Severity label (e.g., "low", "medium", "high").
    pub severity: String,
    /// Numeric conflict score (v0.1 mirrors overlap duration).
    pub conflict_score: f64,
}

/// Compliance summary for a protocol.
///
/// # Examples
/// ```
/// use liveshark_core::{ComplianceSummary, Violation};
///
/// let summary = ComplianceSummary {
///     protocol: "artnet".to_string(),
///     compliance_percentage: 100.0,
///     violations: vec![Violation {
///         id: "LS-ARTNET-PORT".to_string(),
///         severity: "warning".to_string(),
///         message: "Non-standard port".to_string(),
///         count: 1,
///         examples: Vec::new(),
///     }],
/// };
/// assert_eq!(summary.violations.len(), 1);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceSummary {
    /// Protocol name (e.g., "artnet", "sacn", "udp").
    pub protocol: String,
    /// Compliance percentage (0.0–100.0).
    pub compliance_percentage: f64,
    /// Violations sorted by severity and ID.
    pub violations: Vec<Violation>,
}

/// Single compliance violation record.
///
/// # Examples
/// ```
/// use liveshark_core::Violation;
///
/// let violation = Violation {
///     id: "LS-UDP-TOO-SHORT".to_string(),
///     severity: "error".to_string(),
///     message: "Payload too short".to_string(),
///     count: 1,
///     examples: vec!["source 10.0.0.1:1234 @ 1970-01-01T00:00:00Z".to_string()],
/// };
/// assert_eq!(violation.count, 1);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    /// Stable violation identifier (e.g., `LS-SACN-START-CODE`).
    pub id: String,
    /// Severity label (`error` or `warning`).
    pub severity: String,
    /// Human-readable message explaining the violation.
    pub message: String,
    /// Number of occurrences aggregated into this violation.
    pub count: u64,
    /// At most three example contexts, formatted as `source ip:port @ ts; ...`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub examples: Vec<String>,
}

/// Build a stub report with base fields filled and empty aggregates.
///
/// # Examples
/// ```
/// use liveshark_core::make_stub_report;
///
/// let report = make_stub_report("capture.pcapng", 123);
/// assert_eq!(report.report_version, liveshark_core::REPORT_VERSION);
/// assert!(report.universes.is_empty());
/// ```
pub fn make_stub_report(input_path: &str, input_bytes: u64) -> Report {
    Report {
        report_version: REPORT_VERSION,
        tool: ToolInfo {
            name: "liveshark".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
        generated_at: DEFAULT_GENERATED_AT.to_string(),
        input: InputInfo {
            path: input_path.to_string(),
            bytes: input_bytes,
        },
        capture_summary: None,
        universes: vec![],
        flows: vec![],
        conflicts: vec![],
        compliance: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_omits_optional_fields_when_none() {
        let report = Report {
            report_version: REPORT_VERSION,
            tool: ToolInfo {
                name: "liveshark".to_string(),
                version: "0.1.0".to_string(),
            },
            generated_at: DEFAULT_GENERATED_AT.to_string(),
            input: InputInfo {
                path: "capture.pcapng".to_string(),
                bytes: 1,
            },
            capture_summary: Some(CaptureSummary {
                packets_total: 1,
                time_start: None,
                time_end: None,
            }),
            universes: vec![UniverseSummary {
                universe: 1,
                proto: "artnet".to_string(),
                sources: vec![SourceSummary {
                    source_ip: "10.0.0.1".to_string(),
                    cid: None,
                    source_name: None,
                }],
                fps: None,
                frames_count: 1,
                loss_packets: None,
                loss_rate: None,
                burst_count: None,
                max_burst_len: None,
                jitter_ms: None,
                dup_packets: None,
                reordered_packets: None,
            }],
            flows: vec![FlowSummary {
                app_proto: "udp".to_string(),
                src: "10.0.0.1:1000".to_string(),
                dst: "10.0.0.2:2000".to_string(),
                pps: None,
                bps: None,
                iat_jitter_ms: None,
                max_iat_ms: None,
                pps_peak_1s: None,
                bps_peak_1s: None,
            }],
            conflicts: vec![],
            compliance: vec![],
        };

        let value = serde_json::to_value(&report).expect("report json");
        let capture = value.get("capture_summary").expect("capture_summary");
        assert!(capture.get("time_start").is_none());
        assert!(capture.get("time_end").is_none());

        let universe = &value["universes"][0];
        assert!(universe.get("fps").is_none());
        let source = &universe["sources"][0];
        assert!(source.get("cid").is_none());
        assert!(source.get("source_name").is_none());

        let flow = &value["flows"][0];
        assert!(flow.get("pps").is_none());
        assert!(flow.get("bps").is_none());
        assert!(flow.get("iat_jitter_ms").is_none());
    }
}

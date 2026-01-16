//! LiveShark core library for post-mortem PCAP analysis.
//!
//! This crate exposes the analysis pipeline used by the CLI and tests:
//! packet sources feed the analysis layer, which drives protocol decoders
//! (layout/reader/parser) and aggregates results into a deterministic report.
//! Parsing is byte-oriented and side-effect free; all I/O is isolated in
//! `source` modules.
//!
//! Key guarantees:
//! - Report outputs are deterministic and stable across runs.
//! - DMX frames are reconstructed statefully from partial payloads.
//!
//! References (normative):
//! - `docs/RUST_ARCHITECTURE.md`
//! - `spec/en/LiveShark_Spec.tex`
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    /// Tool name (e.g., "liveshark").
    pub name: String,
    /// Tool version (semver).
    pub version: String,
}

/// Input capture metadata embedded in reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputInfo {
    /// Input path as provided to the analyzer.
    pub path: String,
    /// Input size in bytes.
    pub bytes: u64,
}

/// Basic capture summary (timestamps may be absent).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureSummary {
    /// Total packet count observed in the capture.
    pub packets_total: u64,
    /// RFC3339 timestamp of the first packet (if known).
    pub time_start: Option<String>,
    /// RFC3339 timestamp of the last packet (if known).
    pub time_end: Option<String>,
}

/// Per-universe metrics summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniverseSummary {
    /// Canonical universe identifier (u16).
    pub universe: u16,
    /// Protocol name (e.g., "artnet", "sacn").
    pub proto: String,
    /// Observed sources for this universe (stable order).
    pub sources: Vec<SourceSummary>,
    /// Frames-per-second metric (windowed).
    pub fps: Option<f64>,
    /// Number of reconstructed frames.
    pub frames_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Observed loss packets, when sequence tracking is available.
    pub loss_packets: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Observed loss rate, when sequence tracking is available.
    pub loss_rate: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Number of bursts detected within the window.
    pub burst_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Maximum burst length observed within the window.
    pub max_burst_len: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Inter-arrival jitter in milliseconds, when available.
    pub jitter_ms: Option<f64>,
}

/// Source metadata for a universe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceSummary {
    /// Source IP address as a string.
    pub source_ip: String,
    /// sACN CID in canonical form, when available.
    pub cid: Option<String>,
    /// sACN source name, when available.
    pub source_name: Option<String>,
}

/// Flow-level summary for a UDP endpoint pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowSummary {
    /// Application protocol name (e.g., "udp").
    pub app_proto: String,
    /// Source endpoint in `ip:port` form.
    pub src: String,
    /// Destination endpoint in `ip:port` form.
    pub dst: String,
    /// Packets per second (windowed).
    pub pps: Option<f64>,
    /// Bytes per second (windowed).
    pub bps: Option<f64>,
    /// Inter-arrival jitter in milliseconds (windowed).
    pub iat_jitter_ms: Option<f64>,
}

/// Conflict summary between multiple sources on the same universe.
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// At most three example contexts, formatted as `source ip:port @ ts; ...`.
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

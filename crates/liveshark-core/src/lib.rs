use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

mod analysis;
mod protocols;
mod source;

pub use analysis::{AnalysisError, analyze_pcap_file, analyze_source};
pub use source::{PacketEvent, PacketSource, PcapFileSource, SourceError};

pub const REPORT_VERSION: u32 = 1;

/// Rapport minimal (M0).
/// Objectif : format stable + versionné, même avant le parsing réel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub report_version: u32,
    pub tool: ToolInfo,
    pub generated_at: String,

    pub input: InputInfo,

    /// Champs prévus, encore vides en M0.
    pub capture_summary: Option<CaptureSummary>,
    pub universes: Vec<UniverseSummary>,
    pub flows: Vec<FlowSummary>,
    pub conflicts: Vec<ConflictSummary>,
    pub compliance: Vec<ComplianceSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputInfo {
    pub path: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureSummary {
    pub packets_total: u64,
    pub time_start: Option<String>,
    pub time_end: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniverseSummary {
    pub universe: u16,
    pub proto: String,
    pub sources: Vec<SourceSummary>,
    pub fps: Option<f64>,
    pub frames_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loss_packets: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loss_rate: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub burst_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_burst_len: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jitter_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceSummary {
    pub source_ip: String,
    pub cid: Option<String>,
    pub source_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowSummary {
    pub app_proto: String,
    pub src: String,
    pub dst: String,
    pub pps: Option<f64>,
    pub bps: Option<f64>,
    pub iat_jitter_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictSummary {
    pub universe: u16,
    pub sources: Vec<String>,
    pub overlap_duration_s: f64,
    pub affected_channels: Vec<u16>,
    pub severity: String,
    pub conflict_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceSummary {
    pub protocol: String,
    pub compliance_percentage: f64,
    pub violations: Vec<Violation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    pub id: String,
    pub severity: String,
    pub message: String,
}

/// Fabrique un report stub (M0) avec les champs de base remplis.
pub fn make_stub_report(input_path: &str, input_bytes: u64) -> Report {
    let now = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());

    Report {
        report_version: REPORT_VERSION,
        tool: ToolInfo {
            name: "liveshark".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
        generated_at: now,
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

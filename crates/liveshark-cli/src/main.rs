//! LiveShark command-line interface.
//!
//! This binary runs offline analysis for PCAP/PCAPNG captures and emits a
//! deterministic JSON report to a file path you provide. It is a thin wrapper
//! over the `liveshark-core` analysis pipeline and follows the contract
//! defined in `spec/en/LiveShark_Spec.tex`.
//!
//! Typical usage:
//! - `liveshark analyse capture.pcapng -o report.json`
//! - `liveshark analyze capture.pcap -o report.json`
//! - `liveshark pcap analyse capture.pcapng --report report.json`
//!
//! Errors are reported to stderr; a non-zero exit code indicates failure to
//! read the input capture or to write the report.
//!
//! Version française (résumé):
//! L'outil CLI analyse des captures PCAP/PCAPNG et écrit un rapport JSON
//! déterministe. Les erreurs sont affichées sur stderr et retournent un code
//! non nul en cas d'échec.
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use glob::glob;
use liveshark_core::PacketSource;
use serde::Serialize;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Parser, Debug)]
#[command(name = "liveshark")]
#[command(
    version = concat!(
        env!("CARGO_PKG_VERSION"),
        " (commit ",
        env!("LIVESHARK_BUILD_COMMIT"),
        ", built ",
        env!("LIVESHARK_BUILD_DATE"),
        ")"
    )
)]
#[command(
    about = "Offline-first analyzer for show-control network captures (Art-Net / sACN).",
    long_about = None,
    after_help = "Examples:\n  liveshark analyse capture.pcapng -o report.json\n  liveshark analyze capture.pcap -o report.json\n  liveshark pcap analyse capture.pcapng --report report.json\n  liveshark pcap follow capture.pcapng --report report.json"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Operations on PCAP/PCAPNG inputs (offline-first).
    Pcap {
        #[command(subcommand)]
        command: PcapCommands,
    },
}

#[derive(Subcommand, Debug)]
enum PcapCommands {
    /// Analyse a capture file and generate a versioned JSON report (P0: UDP flows).
    #[command(alias = "analyze")]
    #[command(
        after_help = "Examples:\n  liveshark analyse capture.pcapng -o report.json\n  liveshark analyze capture.pcap -o report.json\n  liveshark pcap analyse capture.pcapng --report report.json\n  liveshark pcap follow capture.pcapng --report report.json"
    )]
    Analyse {
        /// Path to a .pcap or .pcapng file
        input: PathBuf,

        /// Output report path (JSON)
        #[arg(short = 'o', long, required_unless_present = "stdout")]
        report: Option<PathBuf>,

        /// Write JSON report to stdout
        #[arg(long, conflicts_with = "report")]
        stdout: bool,

        /// Pretty-print JSON output
        #[arg(long, conflicts_with = "compact")]
        pretty: bool,

        /// Compact JSON output (default)
        #[arg(long)]
        compact: bool,

        /// Suppress non-error output
        #[arg(long)]
        quiet: bool,

        /// Exit with a non-zero code if compliance violations are present
        #[arg(long)]
        strict: bool,

        /// List compliance violations after analysis
        #[arg(long)]
        list_violations: bool,
    },
    /// Follow a capture file that is still growing and rewrite full reports.
    Follow {
        /// Path to a .pcap or .pcapng file
        input: PathBuf,

        /// Output report path (JSON)
        #[arg(short = 'o', long, required_unless_present = "stdout")]
        report: Option<PathBuf>,

        /// Write JSON report to stdout
        #[arg(long, conflicts_with = "report")]
        stdout: bool,

        /// Pretty-print JSON output
        #[arg(long, conflicts_with = "compact")]
        pretty: bool,

        /// Compact JSON output (default)
        #[arg(long)]
        compact: bool,

        /// Suppress non-error output
        #[arg(long)]
        quiet: bool,

        /// Exit with a non-zero code if compliance violations are present
        #[arg(long)]
        strict: bool,

        /// List compliance violations after analysis
        #[arg(long)]
        list_violations: bool,

        /// Loop interval in milliseconds
        #[arg(long, default_value_t = 1000)]
        interval_ms: u64,

        /// Stop after N iterations (tests only).
        #[arg(long, hide = true)]
        max_iterations: Option<u64>,
    },
    /// Show capture metadata (no protocol analysis).
    Info {
        /// Path to a .pcap or .pcapng file
        input: PathBuf,

        /// Output JSON metadata to stdout
        #[arg(long)]
        json: bool,

        /// Pretty-print JSON output
        #[arg(long, conflicts_with = "compact")]
        pretty: bool,

        /// Compact JSON output (default)
        #[arg(long)]
        compact: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Pcap { command } => match command {
            PcapCommands::Analyse {
                input,
                report,
                stdout,
                pretty,
                compact,
                quiet,
                strict,
                list_violations,
            } => cmd_pcap_analyse(
                input,
                report,
                stdout,
                pretty,
                compact,
                quiet,
                strict,
                list_violations,
            ),
            PcapCommands::Info {
                input,
                json,
                pretty,
                compact,
            } => cmd_pcap_info(input, json, pretty, compact),
            PcapCommands::Follow {
                input,
                report,
                stdout,
                pretty,
                compact,
                quiet,
                strict,
                list_violations,
                interval_ms,
                max_iterations,
            } => cmd_pcap_follow(
                input,
                report,
                stdout,
                pretty,
                compact,
                quiet,
                strict,
                list_violations,
                interval_ms,
                max_iterations,
            ),
        },
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {}", err.message);
            if let Some(hint) = err.hint {
                eprintln!("hint: {}", hint);
            }
            ExitCode::from(2)
        }
    }
}

#[derive(Debug)]
struct CliError {
    message: String,
    hint: Option<String>,
}

impl CliError {
    fn new(message: impl Into<String>, hint: Option<String>) -> Self {
        Self {
            message: message.into(),
            hint,
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CliError {}

impl From<anyhow::Error> for CliError {
    fn from(err: anyhow::Error) -> Self {
        CliError::new(err.to_string(), None)
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_pcap_analyse(
    input: PathBuf,
    report: Option<PathBuf>,
    stdout: bool,
    pretty: bool,
    compact: bool,
    quiet: bool,
    strict: bool,
    list_violations: bool,
) -> Result<(), CliError> {
    let resolved_input = resolve_input_path(&input)?;
    validate_input_file(&resolved_input)?;
    let input_abs = fs::canonicalize(&resolved_input)
        .with_context(|| format!("Failed to resolve input path: {}", resolved_input.display()))?;
    let report = if stdout {
        None
    } else {
        Some(report.ok_or_else(|| {
            CliError::new(
                "missing report output",
                Some("pass --report <FILE> or use --stdout".to_string()),
            )
        })?)
    };

    if let Some(report_path) = report.as_ref() {
        let report_abs = report_path
            .parent()
            .map(|parent| {
                if parent.as_os_str().is_empty() {
                    fs::canonicalize(".")
                } else {
                    fs::canonicalize(parent)
                }
            })
            .transpose()
            .with_context(|| format!("Failed to resolve output path: {}", report_path.display()))?;
        if let Some(report_dir) = report_abs {
            let report_target = report_dir.join(
                report_path
                    .file_name()
                    .ok_or_else(|| anyhow::anyhow!("Invalid report path"))?,
            );
            if report_target == input_abs {
                return Err(CliError::new(
                    format!(
                        "report path must differ from input: {}",
                        report_path.display()
                    ),
                    Some("choose a different output path".to_string()),
                ));
            }
        }
    }

    let meta = fs::metadata(&resolved_input)
        .with_context(|| format!("Failed to read input file: {}", resolved_input.display()))?;

    if !meta.is_file() {
        return Err(CliError::new(
            format!("input is not a file: {}", input.display()),
            Some("use a .pcap or .pcapng file".to_string()),
        ));
    }

    let rep = liveshark_core::analyze_pcap_file(&resolved_input)
        .context("PCAP/PCAPNG analysis failed")?;
    let json = serialize_json(&rep, pretty, compact)?;

    if stdout {
        print!("{}", json);
        if list_violations && !quiet {
            let summary = violations_summary(&rep);
            print_violations_summary(&summary);
        }
        if strict && has_violations(&rep) {
            return Err(CliError::new(
                "compliance violations detected",
                Some("use --list-violations to inspect".to_string()),
            ));
        }
        return Ok(());
    }

    let report = report.ok_or_else(|| {
        CliError::new(
            "missing report output",
            Some("pass --report <FILE> or use --stdout".to_string()),
        )
    })?;
    if let Some(parent) = report.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create output directory: {}", parent.display())
            })?;
        }
    }

    fs::write(&report, json)
        .with_context(|| format!("Failed to write report: {}", report.display()))?;

    if list_violations && !quiet {
        let summary = violations_summary(&rep);
        print_violations_summary(&summary);
    }
    if !quiet {
        eprintln!("OK: report written -> {}", report.display());
    }
    if strict && has_violations(&rep) {
        return Err(CliError::new(
            "compliance violations detected",
            Some("use --list-violations to inspect".to_string()),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_pcap_follow(
    input: PathBuf,
    report: Option<PathBuf>,
    stdout: bool,
    pretty: bool,
    compact: bool,
    quiet: bool,
    strict: bool,
    list_violations: bool,
    interval_ms: u64,
    max_iterations: Option<u64>,
) -> Result<(), CliError> {
    let resolved_input = resolve_input_path(&input)?;
    validate_input_file(&resolved_input)?;
    let input_abs = fs::canonicalize(&resolved_input)
        .with_context(|| format!("Failed to resolve input path: {}", resolved_input.display()))?;

    let report = if stdout {
        None
    } else {
        Some(report.ok_or_else(|| {
            CliError::new(
                "missing report output",
                Some("pass --report <FILE> or use --stdout".to_string()),
            )
        })?)
    };

    if let Some(report_path) = report.as_ref() {
        let report_abs = report_path
            .parent()
            .map(|parent| {
                if parent.as_os_str().is_empty() {
                    fs::canonicalize(".")
                } else {
                    fs::canonicalize(parent)
                }
            })
            .transpose()
            .with_context(|| format!("Failed to resolve output path: {}", report_path.display()))?;
        if let Some(report_dir) = report_abs {
            let report_target = report_dir.join(
                report_path
                    .file_name()
                    .ok_or_else(|| anyhow::anyhow!("Invalid report path"))?,
            );
            if report_target == input_abs {
                return Err(CliError::new(
                    format!(
                        "report path must differ from input: {}",
                        report_path.display()
                    ),
                    Some("choose a different output path".to_string()),
                ));
            }
        }
    }

    let mut last_seen: Option<FollowSeen> = None;
    let mut last_violations: Option<Vec<ViolationSummary>> = None;
    let mut last_warning: Option<Instant> = None;
    let mut iterations = 0u64;
    let interval = Duration::from_millis(interval_ms);

    loop {
        if let Some(max) = max_iterations {
            if iterations >= max {
                break;
            }
        }
        iterations += 1;

        let meta = fs::metadata(&resolved_input)
            .with_context(|| format!("Failed to read input file: {}", resolved_input.display()))?;
        if !meta.is_file() {
            return Err(CliError::new(
                format!("input is not a file: {}", input.display()),
                Some("use a .pcap or .pcapng file".to_string()),
            ));
        }

        let current = FollowSeen {
            size_bytes: meta.len(),
            modified: meta.modified().ok(),
        };
        let (changed, rotated) = follow_should_analyze(current, last_seen);
        if rotated {
            last_violations = None;
        }
        last_seen = Some(current);

        if !changed {
            if !quiet {
                eprintln!("follow: no change");
            }
            sleep_interval(interval);
            continue;
        }

        if !quiet {
            eprintln!("follow: analyzing {}", resolved_input.display());
        }

        match liveshark_core::analyze_pcap_file(&resolved_input) {
            Ok(rep) => {
                let json = serialize_json(&rep, pretty, compact)?;
                if stdout {
                    println!("{}", json);
                } else if let Some(report_path) = report.as_ref() {
                    write_report_atomic(report_path, &json)?;
                }

                if list_violations && !quiet {
                    let summary = violations_summary(&rep);
                    if last_violations.as_ref() != Some(&summary) {
                        print_violations_summary(&summary);
                        last_violations = Some(summary);
                    }
                }

                if !quiet {
                    if let Some(report_path) = report.as_ref() {
                        eprintln!("OK: report written -> {}", report_path.display());
                    } else {
                        eprintln!("OK: report emitted");
                    }
                }
                if strict && has_violations(&rep) {
                    return Err(CliError::new(
                        "compliance violations detected",
                        Some("use --list-violations to inspect".to_string()),
                    ));
                }
            }
            Err(err) => {
                if is_transient_error(&err) {
                    if !quiet && should_warn(&mut last_warning) {
                        eprintln!("warning: capture appears incomplete; retrying ({})", err);
                    }
                } else {
                    return Err(CliError::new(
                        format!("PCAP/PCAPNG analysis failed: {err}"),
                        Some("check capture integrity or permissions".to_string()),
                    ));
                }
            }
        }

        sleep_interval(interval);
    }

    Ok(())
}

fn serialize_json<T: Serialize>(
    value: &T,
    pretty: bool,
    compact: bool,
) -> Result<String, CliError> {
    if pretty && compact {
        return Err(CliError::new(
            "cannot use --pretty and --compact together",
            Some("choose one output format".to_string()),
        ));
    }
    if pretty {
        serde_json::to_string_pretty(value)
            .context("JSON serialization failed")
            .map_err(Into::into)
    } else {
        serde_json::to_string(value)
            .context("JSON serialization failed")
            .map_err(Into::into)
    }
}

fn has_violations(rep: &liveshark_core::Report) -> bool {
    rep.compliance
        .iter()
        .any(|entry| !entry.violations.is_empty())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ViolationSummary {
    protocol: String,
    id: String,
    count: u64,
}

fn violations_summary(rep: &liveshark_core::Report) -> Vec<ViolationSummary> {
    let mut summary = Vec::new();
    for entry in &rep.compliance {
        for violation in &entry.violations {
            summary.push(ViolationSummary {
                protocol: entry.protocol.clone(),
                id: violation.id.clone(),
                count: violation.count,
            });
        }
    }
    summary.sort_by(|a, b| a.protocol.cmp(&b.protocol).then_with(|| a.id.cmp(&b.id)));
    summary
}

fn print_violations_summary(summary: &[ViolationSummary]) {
    eprintln!("Compliance violations:");
    for item in summary {
        eprintln!("  {} {} ({})", item.protocol, item.id, item.count);
    }
}

#[derive(Debug, Clone, Copy)]
struct FollowSeen {
    size_bytes: u64,
    modified: Option<SystemTime>,
}

fn follow_should_analyze(current: FollowSeen, last: Option<FollowSeen>) -> (bool, bool) {
    let mut rotated = false;
    let changed = match last {
        None => true,
        Some(prev) => match current.size_bytes.cmp(&prev.size_bytes) {
            std::cmp::Ordering::Less => {
                rotated = true;
                true
            }
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Equal => match (current.modified, prev.modified) {
                (Some(now), Some(then)) => now > then,
                _ => false,
            },
        },
    };
    (changed, rotated)
}

fn write_report_atomic(path: &Path, json: &str) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create output directory: {}", parent.display())
            })?;
        }
    }

    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp_path = PathBuf::from(tmp);

    fs::write(&tmp_path, json)
        .with_context(|| format!("Failed to write report: {}", tmp_path.display()))?;

    if let Err(err) = fs::rename(&tmp_path, path) {
        if path.exists() {
            fs::remove_file(path)
                .with_context(|| format!("Failed to replace report: {}", path.display()))?;
            fs::rename(&tmp_path, path)
                .with_context(|| format!("Failed to replace report: {}", path.display()))?;
        } else {
            return Err(CliError::new(
                format!("Failed to move report into place: {err}"),
                Some("check write permissions".to_string()),
            ));
        }
    }

    Ok(())
}

fn is_transient_error(err: &dyn std::fmt::Display) -> bool {
    let msg = err.to_string().to_lowercase();
    msg.contains("incomplete") || msg.contains("unexpected end") || msg.contains("eof")
}

fn should_warn(last_warning: &mut Option<Instant>) -> bool {
    let now = Instant::now();
    let emit = last_warning
        .map(|last| now.duration_since(last) >= Duration::from_secs(5))
        .unwrap_or(true);
    if emit {
        *last_warning = Some(now);
    }
    emit
}

fn sleep_interval(interval: Duration) {
    if interval.is_zero() {
        return;
    }
    thread::sleep(interval);
}

fn validate_input_file(input: &Path) -> Result<(), CliError> {
    if !input.exists() {
        return Err(CliError::new(
            format!("input file not found: {}", input.display()),
            Some("use a .pcap or .pcapng file".to_string()),
        ));
    }
    let ext = input
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if ext != "pcap" && ext != "pcapng" {
        return Err(CliError::new(
            format!("unsupported input format '{}'", input.display()),
            Some("expected a .pcap or .pcapng file".to_string()),
        ));
    }
    Ok(())
}

fn cmd_pcap_info(input: PathBuf, json: bool, pretty: bool, compact: bool) -> Result<(), CliError> {
    let resolved_input = resolve_input_path(&input)?;
    validate_input_file(&resolved_input)?;
    let meta = fs::metadata(&resolved_input)
        .with_context(|| format!("Failed to read input file: {}", resolved_input.display()))?;

    let info = collect_pcap_info(&resolved_input, meta.len())?;
    let json_output = json || pretty || compact;
    if json_output {
        let json = serialize_json(&info, pretty, compact)?;
        print!("{}", json);
        return Ok(());
    }

    println!("file: {}", info.path);
    println!("format: {}", info.capture_type);
    println!("bytes: {}", info.size_bytes);
    println!("packets: {}", info.packets);
    println!(
        "time_start: {}",
        info.first_ts.as_deref().unwrap_or("unknown")
    );
    println!("time_end: {}", info.last_ts.as_deref().unwrap_or("unknown"));
    println!("duration_s: {}", info.duration_s.unwrap_or(0.0));
    println!(
        "linktype: {}",
        info.linktype.as_deref().unwrap_or("unknown")
    );
    Ok(())
}

#[derive(Debug, Serialize)]
struct PcapInfo {
    path: String,
    size_bytes: u64,
    capture_type: String,
    packets: u64,
    first_ts: Option<String>,
    last_ts: Option<String>,
    duration_s: Option<f64>,
    linktype: Option<String>,
}

fn collect_pcap_info(input: &Path, size_bytes: u64) -> Result<PcapInfo, CliError> {
    let capture_type = input
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("unknown")
        .to_ascii_lowercase();
    let mut source = liveshark_core::PcapFileSource::open(input)
        .map_err(|err| CliError::new(err.to_string(), None))?;
    let mut packets = 0u64;
    let mut first_ts = None;
    let mut last_ts = None;
    let mut linktype = None;
    while let Some(event) = source
        .next_packet()
        .map_err(|err| CliError::new(err.to_string(), None))?
    {
        packets += 1;
        if linktype.is_none() {
            linktype = Some(format!("{:?}", event.linktype));
        }
        update_ts_bounds(&mut first_ts, &mut last_ts, event.ts);
    }

    let duration_s = match (first_ts, last_ts) {
        (Some(start), Some(end)) if end >= start => Some(end - start),
        _ => None,
    };

    Ok(PcapInfo {
        path: input.display().to_string(),
        size_bytes,
        capture_type,
        packets,
        first_ts: ts_to_rfc3339(first_ts),
        last_ts: ts_to_rfc3339(last_ts),
        duration_s,
        linktype,
    })
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

fn resolve_input_path(input: &Path) -> Result<PathBuf, CliError> {
    let pattern = input.to_string_lossy();
    if !is_glob_pattern(&pattern) {
        return Ok(input.to_path_buf());
    }

    let mut matches = Vec::new();
    let paths = glob(&pattern).map_err(|err| {
        CliError::new(
            format!("invalid input pattern '{}'", pattern),
            Some(format!("pattern error: {}", err.msg)),
        )
    })?;
    for entry in paths {
        let path = entry.map_err(|err| {
            CliError::new(
                format!("invalid input pattern '{}'", pattern),
                Some(format!("pattern error: {}", err)),
            )
        })?;
        if path.is_file() {
            matches.push(path);
        }
    }

    if matches.is_empty() {
        return Err(CliError::new(
            format!("no files match pattern '{}'", pattern),
            Some("check the path or quote the pattern; expected .pcap or .pcapng".to_string()),
        ));
    }
    if matches.len() > 1 {
        let hint = "pass a single capture file, or run once per file".to_string();
        let mut message = format!(
            "multiple files match pattern '{}' ({} matches)",
            pattern,
            matches.len()
        );
        let listed = matches.iter().take(3).collect::<Vec<_>>();
        if !listed.is_empty() {
            let mut details = String::new();
            details.push_str("; matches: ");
            details.push_str(
                &listed
                    .into_iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            if matches.len() > 3 {
                details.push_str(", ...");
            }
            message.push_str(&details);
        }
        return Err(CliError::new(message, Some(hint)));
    }

    Ok(matches.remove(0))
}

fn is_glob_pattern(input: &str) -> bool {
    input.contains('*') || input.contains('?') || input.contains('[')
}

#[cfg(test)]
mod tests {
    use super::cmd_pcap_analyse;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn missing_report_output_is_an_error() {
        let temp = TempDir::new().expect("tempdir");
        let input = temp.path().join("capture.pcapng");
        std::fs::write(&input, []).expect("write capture");

        let err = cmd_pcap_analyse(
            PathBuf::from(&input),
            None,
            false,
            false,
            false,
            true,
            false,
            false,
        )
        .expect_err("missing report should error");

        assert_eq!(err.message, "missing report output");
        assert_eq!(
            err.hint.as_deref(),
            Some("pass --report <FILE> or use --stdout")
        );
    }
}

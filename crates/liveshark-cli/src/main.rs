use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use glob::glob;

#[derive(Parser, Debug)]
#[command(name = "liveshark")]
#[command(version)]
#[command(
    about = "Offline-first analyzer for show-control network captures (Art-Net / sACN).",
    long_about = None,
    after_help = "Examples:\n  liveshark analyse capture.pcapng -o report.json\n  liveshark analyze capture.pcap -o report.json\n  liveshark pcap analyse capture.pcapng --report report.json"
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
        after_help = "Examples:\n  liveshark analyse capture.pcapng -o report.json\n  liveshark analyze capture.pcap -o report.json\n  liveshark pcap analyse capture.pcapng --report report.json"
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
                "missing output path",
                Some("use -o/--report or --stdout".to_string()),
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
    let json = serialize_report(&rep, pretty, compact)?;

    if stdout {
        print!("{}", json);
        if list_violations && !quiet {
            print_violations(&rep);
        }
        if strict && has_violations(&rep) {
            return Err(CliError::new(
                "compliance violations detected",
                Some("use --list-violations to inspect".to_string()),
            ));
        }
        return Ok(());
    }

    let report = report.expect("report required when not using stdout");
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
        print_violations(&rep);
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

fn serialize_report(
    rep: &liveshark_core::Report,
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
        serde_json::to_string_pretty(rep)
            .context("JSON serialization failed")
            .map_err(Into::into)
    } else {
        serde_json::to_string(rep)
            .context("JSON serialization failed")
            .map_err(Into::into)
    }
}

fn has_violations(rep: &liveshark_core::Report) -> bool {
    rep.compliance
        .iter()
        .any(|entry| !entry.violations.is_empty())
}

fn print_violations(rep: &liveshark_core::Report) {
    let mut entries: Vec<_> = rep.compliance.iter().collect();
    entries.sort_by(|a, b| a.protocol.cmp(&b.protocol));
    eprintln!("Compliance violations:");
    for entry in entries {
        let mut violations = entry.violations.clone();
        violations.sort_by(|a, b| a.id.cmp(&b.id));
        for violation in violations {
            eprintln!(
                "  {} {} ({})",
                entry.protocol, violation.id, violation.count
            );
        }
    }
}

fn validate_input_file(input: &PathBuf) -> Result<(), CliError> {
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

fn resolve_input_path(input: &PathBuf) -> Result<PathBuf, CliError> {
    let pattern = input.to_string_lossy();
    if !is_glob_pattern(&pattern) {
        return Ok(input.clone());
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

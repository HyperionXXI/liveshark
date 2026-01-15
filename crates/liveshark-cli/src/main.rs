use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

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
        #[arg(short = 'o', long)]
        report: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Pcap { command } => match command {
            PcapCommands::Analyse { input, report } => cmd_pcap_analyse(input, report)
                .map_err(|err| err.with_context("PCAP/PCAPNG analysis failed")),
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

    fn with_context(self, context: &str) -> Self {
        Self {
            message: format!("{}: {}", context, self.message),
            hint: self.hint,
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

fn cmd_pcap_analyse(input: PathBuf, report: PathBuf) -> Result<(), CliError> {
    validate_input_file(&input)?;
    let input_abs = fs::canonicalize(&input)
        .with_context(|| format!("Failed to resolve input path: {}", input.display()))?;
    let report_abs = report
        .parent()
        .map(|parent| {
            if parent.as_os_str().is_empty() {
                fs::canonicalize(".")
            } else {
                fs::canonicalize(parent)
            }
        })
        .transpose()
        .with_context(|| format!("Failed to resolve output path: {}", report.display()))?;
    if let Some(report_dir) = report_abs {
        let report_target = report_dir.join(
            report
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("Invalid report path"))?,
        );
        if report_target == input_abs {
            return Err(CliError::new(
                format!("report path must differ from input: {}", report.display()),
                Some("choose a different output path".to_string()),
            ));
        }
    }

    let meta = fs::metadata(&input)
        .with_context(|| format!("Failed to read input file: {}", input.display()))?;

    if !meta.is_file() {
        return Err(CliError::new(
            format!("input is not a file: {}", input.display()),
            Some("use a .pcap or .pcapng file".to_string()),
        ));
    }

    let rep = liveshark_core::analyze_pcap_file(&input).context("PCAP/PCAPNG analysis failed")?;
    let json = serde_json::to_string_pretty(&rep).context("JSON serialization failed")?;

    if let Some(parent) = report.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create output directory: {}", parent.display())
            })?;
        }
    }

    fs::write(&report, json)
        .with_context(|| format!("Failed to write report: {}", report.display()))?;

    eprintln!("OK: report written -> {}", report.display());
    Ok(())
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
            format!("unsupported input extension: {}", input.display()),
            Some("use a .pcap or .pcapng file".to_string()),
        ));
    }
    Ok(())
}

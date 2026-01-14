use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "liveshark")]
#[command(version)]
#[command(
    about = "Offline-first analyzer for show-control network captures (Art-Net / sACN).",
    long_about = None
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
    Analyse {
        /// Path to a .pcap or .pcapng file
        input: PathBuf,

        /// Output report path (JSON)
        #[arg(long)]
        report: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Pcap { command } => match command {
            PcapCommands::Analyse { input, report } => cmd_pcap_analyse(input, report),
        },
    }
}

fn cmd_pcap_analyse(input: PathBuf, report: PathBuf) -> Result<()> {
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
            anyhow::bail!("Report path must differ from input: {}", report.display());
        }
    }

    let meta = fs::metadata(&input)
        .with_context(|| format!("Failed to read input file: {}", input.display()))?;

    if !meta.is_file() {
        anyhow::bail!("Invalid input (not a file): {}", input.display());
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

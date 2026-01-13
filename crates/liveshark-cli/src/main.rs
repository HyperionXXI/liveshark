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
    /// Analyse a capture file and generate a versioned JSON report (M0: stub report).
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
    let meta = fs::metadata(&input)
        .with_context(|| format!("Impossible de lire le fichier d'entrée: {}", input.display()))?;

    if !meta.is_file() {
        anyhow::bail!("Entrée invalide (pas un fichier): {}", input.display());
    }

    // M0: report stub, stable & versioned.
    let rep = liveshark_core::make_stub_report(&input.display().to_string(), meta.len());
    let json = serde_json::to_string_pretty(&rep).context("Échec sérialisation JSON")?;

    if let Some(parent) = report.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!("Impossible de créer le dossier de sortie: {}", parent.display())
            })?;
        }
    }

    fs::write(&report, json)
        .with_context(|| format!("Impossible d'écrire le report: {}", report.display()))?;

    eprintln!("OK: report écrit -> {}", report.display());
    Ok(())
}

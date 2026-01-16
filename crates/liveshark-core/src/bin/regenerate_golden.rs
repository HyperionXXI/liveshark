use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use liveshark_core::analyze_pcap_file;

fn main() -> ExitCode {
    if let Err(err) = run() {
        eprintln!("error: {}", err);
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn run() -> Result<(), String> {
    let root = PathBuf::from("tests").join("golden");
    let entries =
        fs::read_dir(&root).map_err(|err| format!("failed to read {}: {}", root.display(), err))?;

    for entry in entries {
        let entry = entry.map_err(|err| format!("failed to read entry: {}", err))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let input = path.join("input.pcapng");
        if !input.exists() {
            continue;
        }
        let output = path.join("expected_report.json");
        regenerate_one(&input, &output)?;
    }

    Ok(())
}

fn regenerate_one(input: &Path, output: &Path) -> Result<(), String> {
    let report = analyze_pcap_file(input)
        .map_err(|err| format!("analysis failed for {}: {}", input.display(), err))?;
    let json = serde_json::to_string(&report)
        .map_err(|err| format!("JSON serialization failed: {}", err))?;
    fs::write(output, json)
        .map_err(|err| format!("failed to write {}: {}", output.display(), err))?;
    Ok(())
}

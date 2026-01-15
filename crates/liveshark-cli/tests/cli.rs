use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;
use serde_json::Value;
use tempfile::TempDir;

fn cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("liveshark"))
}

fn repo_root() -> std::path::PathBuf {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root")
        .to_path_buf()
}

fn sample_capture() -> std::path::PathBuf {
    repo_root()
        .join("tests")
        .join("golden")
        .join("artnet")
        .join("input.pcapng")
}

#[test]
fn help_supports_analyse_and_analyze() {
    cmd()
        .arg("pcap")
        .arg("analyse")
        .arg("--help")
        .assert()
        .success();
    cmd()
        .arg("pcap")
        .arg("analyze")
        .arg("--help")
        .assert()
        .success();
}

#[test]
fn missing_input_shows_error_and_hint() {
    let temp = TempDir::new().expect("tempdir");
    let missing = temp.path().join("missing.pcapng");
    let report = temp.path().join("report.json");

    cmd()
        .arg("pcap")
        .arg("analyze")
        .arg(missing)
        .arg("-o")
        .arg(report)
        .assert()
        .failure()
        .stderr(contains("error:").and(contains("hint:")));
}

#[test]
fn stdout_outputs_json() {
    let input = sample_capture();
    let assert = cmd()
        .arg("pcap")
        .arg("analyze")
        .arg(input)
        .arg("--stdout")
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).expect("utf8 stdout");
    let _: Value = serde_json::from_str(&stdout).expect("valid json");
}

#[test]
fn stdout_and_report_conflict() {
    let temp = TempDir::new().expect("tempdir");
    let input = sample_capture();
    let report = temp.path().join("report.json");

    cmd()
        .arg("pcap")
        .arg("analyze")
        .arg(input)
        .arg("--stdout")
        .arg("-o")
        .arg(report)
        .assert()
        .failure()
        .stderr(contains("error:"));
}

#[test]
fn pretty_and_compact_conflict() {
    let temp = TempDir::new().expect("tempdir");
    let input = sample_capture();
    let report = temp.path().join("report.json");

    cmd()
        .arg("pcap")
        .arg("analyze")
        .arg(input)
        .arg("-o")
        .arg(report)
        .arg("--pretty")
        .arg("--compact")
        .assert()
        .failure()
        .stderr(contains("error:"));
}

#[test]
fn quiet_suppresses_ok_message() {
    let temp = TempDir::new().expect("tempdir");
    let input = sample_capture();
    let report = temp.path().join("report.json");

    cmd()
        .arg("pcap")
        .arg("analyze")
        .arg(input)
        .arg("-o")
        .arg(report)
        .arg("--quiet")
        .assert()
        .success()
        .stderr(predicates::str::contains("OK:").not());
}

#[test]
fn list_violations_outputs_ids() {
    let temp = TempDir::new().expect("tempdir");
    let input = sample_capture();
    let report = temp.path().join("report.json");

    cmd()
        .arg("pcap")
        .arg("analyze")
        .arg(input)
        .arg("-o")
        .arg(report)
        .arg("--list-violations")
        .assert()
        .success()
        .stderr(contains("Compliance violations:").and(contains("LS-SACN-TOO-SHORT")));
}

#[test]
fn strict_fails_when_violations_present() {
    let temp = TempDir::new().expect("tempdir");
    let input = sample_capture();
    let report = temp.path().join("report.json");

    cmd()
        .arg("pcap")
        .arg("analyze")
        .arg(input)
        .arg("-o")
        .arg(report)
        .arg("--strict")
        .assert()
        .failure()
        .stderr(contains("compliance violations detected"));
}

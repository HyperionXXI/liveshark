use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;
use predicates::str::is_match;
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
fn version_includes_commit() {
    cmd()
        .arg("--version")
        .assert()
        .success()
        .stdout(contains("commit").and(is_match(r"commit\s+\w+").expect("regex")));
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

#[test]
fn glob_no_match_errors() {
    let temp = TempDir::new().expect("tempdir");
    let pattern = temp.path().join("*.pcapng");
    let report = temp.path().join("report.json");

    cmd()
        .arg("pcap")
        .arg("analyze")
        .arg(pattern.to_string_lossy().to_string())
        .arg("-o")
        .arg(report)
        .assert()
        .failure()
        .stderr(contains("error: no files match pattern").and(contains("hint:")));
}

#[test]
fn glob_multiple_matches_errors() {
    let temp = TempDir::new().expect("tempdir");
    let file_a = temp.path().join("a.pcapng");
    let file_b = temp.path().join("b.pcapng");
    std::fs::write(&file_a, []).expect("write file");
    std::fs::write(&file_b, []).expect("write file");

    let report = temp.path().join("report.json");
    let pattern = temp.path().join("*.pcapng");

    cmd()
        .arg("pcap")
        .arg("analyze")
        .arg(pattern.to_string_lossy().to_string())
        .arg("-o")
        .arg(report)
        .assert()
        .failure()
        .stderr(contains("error: multiple files match pattern").and(contains("hint:")));
}

#[test]
fn invalid_extension_is_rejected() {
    let temp = TempDir::new().expect("tempdir");
    let input = temp.path().join("capture.txt");
    std::fs::write(&input, "dummy").expect("write file");
    let report = temp.path().join("report.json");

    cmd()
        .arg("pcap")
        .arg("analyze")
        .arg(input)
        .arg("-o")
        .arg(report)
        .assert()
        .failure()
        .stderr(contains("error: unsupported input format").and(contains("hint: expected")));
}

#[test]
fn glob_single_match_is_used() {
    let temp = TempDir::new().expect("tempdir");
    let input = sample_capture();
    let target = temp.path().join("capture.pcapng");
    std::fs::copy(&input, &target).expect("copy capture");

    let report = temp.path().join("report.json");
    let pattern = temp.path().join("*.pcapng");

    cmd()
        .arg("pcap")
        .arg("analyze")
        .arg(pattern.to_string_lossy().to_string())
        .arg("-o")
        .arg(report)
        .assert()
        .success();
}

#[test]
fn pcap_info_outputs_path_and_packets() {
    let input = sample_capture();
    cmd()
        .arg("pcap")
        .arg("info")
        .arg(input.clone())
        .assert()
        .success()
        .stdout(
            contains("path:")
                .and(contains("packets:"))
                .and(contains(input.to_string_lossy().to_string())),
        );
}

#[test]
fn pcap_info_rejects_invalid_extension() {
    let temp = TempDir::new().expect("tempdir");
    let input = temp.path().join("capture.txt");
    std::fs::write(&input, "dummy").expect("write file");

    cmd()
        .arg("pcap")
        .arg("info")
        .arg(input)
        .assert()
        .failure()
        .stderr(contains("error: unsupported input format").and(contains("hint: expected")));
}

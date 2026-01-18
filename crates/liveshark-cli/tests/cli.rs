use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;
use predicates::str::is_match;
use serde_json::Value;
use std::io;
use std::process::Stdio;
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("liveshark"))
}

fn wait_for_nonempty_file(path: &std::path::Path, timeout: Duration) {
    let start = Instant::now();
    loop {
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.len() > 0 {
                return;
            }
        }
        if start.elapsed() > timeout {
            panic!("timed out waiting for {}", path.display());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_absent_file(path: &std::path::Path, timeout: Duration) {
    let start = Instant::now();
    loop {
        match std::fs::metadata(path) {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => return,
            Err(err) => panic!("unexpected metadata error: {}", err),
        }
        if start.elapsed() > timeout {
            panic!("timed out waiting for {}", path.display());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn read_bytes(path: &std::path::Path) -> Vec<u8> {
    std::fs::read(path).expect("read file")
}

fn wait_for_file_change(
    path: &std::path::Path,
    previous_bytes: &[u8],
    timeout: Duration,
) -> Vec<u8> {
    let start = Instant::now();
    loop {
        if let Ok(bytes) = std::fs::read(path) {
            if !bytes.is_empty() && bytes != previous_bytes {
                return bytes;
            }
        }
        if start.elapsed() > timeout {
            panic!("timed out waiting for {}", path.display());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
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
    cmd().arg("--version").assert().success().stdout(
        contains("commit")
            .and(contains("built"))
            .and(is_match(r"commit\s+\w+").expect("regex")),
    );
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
fn follow_writes_report_in_two_iterations() {
    let temp = TempDir::new().expect("tempdir");
    let input = sample_capture();
    let target = temp.path().join("capture.pcapng");
    std::fs::copy(&input, &target).expect("copy capture");
    let report = temp.path().join("out.json");

    cmd()
        .arg("pcap")
        .arg("follow")
        .arg(&target)
        .arg("--report")
        .arg(&report)
        .arg("--interval-ms")
        .arg("0")
        .arg("--max-iterations")
        .arg("2")
        .assert()
        .success();

    let content = std::fs::read_to_string(&report).expect("read report");
    assert!(!content.is_empty());
    let json: Value = serde_json::from_str(&content).expect("valid json");
    assert!(json.get("report_version").is_some());
    assert!(json.get("flows").is_some() || json.get("universes").is_some());
}

#[test]
fn follow_glob_errors_match_analyze_semantics() {
    let temp = TempDir::new().expect("tempdir");
    let report = temp.path().join("report.json");
    let pattern = temp.path().join("*.pcapng");

    cmd()
        .arg("pcap")
        .arg("follow")
        .arg(pattern.to_string_lossy().to_string())
        .arg("--report")
        .arg(&report)
        .arg("--max-iterations")
        .arg("1")
        .assert()
        .failure()
        .stderr(contains("error: no files match pattern").and(contains("hint:")));

    let file_a = temp.path().join("a.pcapng");
    let file_b = temp.path().join("b.pcapng");
    std::fs::write(&file_a, []).expect("write file");
    std::fs::write(&file_b, []).expect("write file");

    cmd()
        .arg("pcap")
        .arg("follow")
        .arg(pattern.to_string_lossy().to_string())
        .arg("--report")
        .arg(&report)
        .arg("--max-iterations")
        .arg("1")
        .assert()
        .failure()
        .stderr(contains("error: multiple files match pattern").and(contains("hint:")));
}

#[test]
fn follow_list_violations_is_not_repeated() {
    let input = sample_capture();
    let assert = cmd()
        .arg("pcap")
        .arg("follow")
        .arg(input)
        .arg("--stdout")
        .arg("--list-violations")
        .arg("--interval-ms")
        .arg("0")
        .arg("--max-iterations")
        .arg("2")
        .assert()
        .success();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).expect("utf8 stderr");
    assert_eq!(stderr.matches("Compliance violations:").count(), 1);
}

#[test]
fn follow_transient_errors_retry_without_change() {
    let temp = TempDir::new().expect("tempdir");
    let input = temp.path().join("capture.pcapng");
    std::fs::write(&input, []).expect("write truncated capture");

    let assert = cmd()
        .arg("pcap")
        .arg("follow")
        .arg(&input)
        .arg("--stdout")
        .arg("--interval-ms")
        .arg("5000")
        .arg("--max-iterations")
        .arg("2")
        .assert()
        .success();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).expect("utf8 stderr");
    assert!(stderr.matches("warning: follow transient:").count() >= 2);
}

#[test]
fn follow_list_violations_is_silent_when_empty() {
    let input = repo_root()
        .join("tests")
        .join("golden")
        .join("flow_only")
        .join("input.pcapng");
    let assert = cmd()
        .arg("pcap")
        .arg("follow")
        .arg(input)
        .arg("--stdout")
        .arg("--list-violations")
        .arg("--interval-ms")
        .arg("0")
        .arg("--max-iterations")
        .arg("1")
        .assert()
        .success();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).expect("utf8 stderr");
    assert!(!stderr.contains("Compliance violations"));
}

#[test]
fn follow_rotation_truncation_triggers_reanalysis() {
    let temp = TempDir::new().expect("tempdir");
    let big = repo_root()
        .join("tests")
        .join("golden")
        .join("sacn_burst")
        .join("input.pcapng");
    let small = repo_root()
        .join("tests")
        .join("golden")
        .join("artnet")
        .join("input.pcapng");
    let target = temp.path().join("capture.pcapng");
    std::fs::copy(&big, &target).expect("copy capture");

    let report = temp.path().join("report.json");
    let child = std::process::Command::new(assert_cmd::cargo::cargo_bin!("liveshark"))
        .arg("pcap")
        .arg("follow")
        .arg(&target)
        .arg("--report")
        .arg(&report)
        .arg("--interval-ms")
        .arg("50")
        .arg("--max-iterations")
        .arg("6")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn follow");

    wait_for_nonempty_file(&report, Duration::from_secs(2));
    let bytes0 = read_bytes(&report);
    std::fs::copy(&small, &target).expect("overwrite capture");
    let _bytes1 = wait_for_file_change(&report, &bytes0, Duration::from_secs(2));

    let output = child.wait_with_output().expect("wait follow");
    assert!(output.status.success());

    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("follow: rotated"));
}

#[test]
fn follow_missing_file_recovers_after_recreate() {
    let temp = TempDir::new().expect("tempdir");
    let input = sample_capture();
    let recreate = repo_root()
        .join("tests")
        .join("golden")
        .join("flow_only")
        .join("input.pcapng");
    let target = temp.path().join("capture.pcapng");
    std::fs::copy(&input, &target).expect("copy capture");

    let report = temp.path().join("report.json");
    cmd()
        .arg("pcap")
        .arg("analyze")
        .arg(&target)
        .arg("--report")
        .arg(&report)
        .arg("--pretty")
        .assert()
        .success();

    let bytes0 = read_bytes(&report);

    let interval = Duration::from_millis(50);
    let child = std::process::Command::new(assert_cmd::cargo::cargo_bin!("liveshark"))
        .arg("pcap")
        .arg("follow")
        .arg(&target)
        .arg("--report")
        .arg(&report)
        .arg("--interval-ms")
        .arg(interval.as_millis().to_string())
        .arg("--max-iterations")
        .arg("8")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn follow");

    let bytes1 = wait_for_file_change(&report, &bytes0, Duration::from_secs(3));
    std::fs::remove_file(&target).expect("remove capture");
    wait_for_absent_file(&target, Duration::from_secs(2));
    std::thread::sleep(Duration::from_millis(
        (interval.as_millis() as u64).saturating_mul(2),
    ));
    std::fs::copy(&recreate, &target).expect("recreate capture");
    let _bytes2 = wait_for_file_change(&report, &bytes1, Duration::from_secs(3));

    let output = child.wait_with_output().expect("wait follow");
    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("warning: follow transient: input missing:"));
}

#[test]
fn pcap_info_outputs_path_and_packets() {
    let input = sample_capture();
    let assert = cmd()
        .arg("pcap")
        .arg("info")
        .arg(input.clone())
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).expect("utf8 stdout");
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(lines.len() >= 7);
    assert!(lines[0].starts_with("file: "));
    assert!(lines[1].starts_with("format: "));
    assert!(lines[2].starts_with("bytes: "));
    assert!(lines[3].starts_with("packets: "));
    assert!(lines[4].starts_with("time_start: "));
    assert!(lines[5].starts_with("time_end: "));
    assert!(lines[6].starts_with("duration_s: "));
    let input_str = input.to_string_lossy();
    assert!(stdout.contains(input_str.as_ref()));
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

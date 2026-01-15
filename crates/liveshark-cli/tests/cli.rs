use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;
use tempfile::TempDir;

fn cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("liveshark"))
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

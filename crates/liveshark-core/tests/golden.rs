use std::fs;
use std::path::Path;

use liveshark_core::{Report, analyze_pcap_file};

fn load_expected_report(dir: &str) -> Report {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    let expected_path = root.join(dir).join("expected_report.json");

    let expected_json = fs::read_to_string(&expected_path).expect("read expected_report.json");
    serde_json::from_str(&expected_json).expect("parse expected report")
}

fn run_golden(dir: &str) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    let input = root.join(dir).join("input.pcapng");
    let expected = load_expected_report(dir);

    let mut actual = analyze_pcap_file(&input).expect("analyze pcap");
    actual.generated_at = expected.generated_at.clone();
    actual.input.path = expected.input.path.clone();

    let actual_value = serde_json::to_value(actual).expect("serialize actual");
    let expected_value = serde_json::to_value(expected).expect("serialize expected");

    assert_eq!(actual_value, expected_value, "golden mismatch in {dir}");
}

#[test]
fn golden_artnet() {
    run_golden("tests/golden/artnet");
}

#[test]
fn golden_sacn() {
    run_golden("tests/golden/sacn");
}

#[test]
fn golden_artnet_conflict() {
    run_golden("tests/golden/artnet_conflict");
}

#[test]
fn golden_sacn_conflict() {
    run_golden("tests/golden/sacn_conflict");
}

#[test]
fn golden_artnet_burst() {
    run_golden("tests/golden/artnet_burst");
}

#[test]
fn golden_artnet_gap() {
    run_golden("tests/golden/artnet_gap");
}

#[test]
fn golden_artnet_burst_has_burst_metrics() {
    let report = load_expected_report("tests/golden/artnet_burst");
    let summary = &report.universes[0];
    assert_eq!(summary.burst_count, Some(2));
    assert_eq!(summary.max_burst_len, Some(3));
    assert_eq!(summary.loss_packets, Some(5));
}

#[test]
fn golden_artnet_gap_has_gap_metrics() {
    let report = load_expected_report("tests/golden/artnet_gap");
    let summary = &report.universes[0];
    assert_eq!(summary.burst_count, Some(1));
    assert_eq!(summary.max_burst_len, Some(7));
    assert_eq!(summary.loss_packets, Some(7));
}

#[test]
fn golden_sacn_burst() {
    run_golden("tests/golden/sacn_burst");
}

#[test]
fn golden_sacn_burst_has_burst_metrics() {
    let report = load_expected_report("tests/golden/sacn_burst");
    let summary = &report.universes[0];
    assert_eq!(summary.burst_count, Some(2));
    assert_eq!(summary.max_burst_len, Some(3));
    assert_eq!(summary.loss_packets, Some(5));
}

#[test]
fn golden_sacn_gap() {
    run_golden("tests/golden/sacn_gap");
}

#[test]
fn golden_sacn_gap_has_gap_metrics() {
    let report = load_expected_report("tests/golden/sacn_gap");
    let summary = &report.universes[0];
    assert_eq!(summary.burst_count, Some(1));
    assert_eq!(summary.max_burst_len, Some(7));
    assert_eq!(summary.loss_packets, Some(7));
}

#[test]
fn golden_flow_only() {
    run_golden("tests/golden/flow_only");
}

#[test]
fn golden_artnet_invalid_length() {
    run_golden("tests/golden/artnet_invalid_length");
}

#[test]
fn golden_sacn_invalid_start_code() {
    run_golden("tests/golden/sacn_invalid_start_code");
}

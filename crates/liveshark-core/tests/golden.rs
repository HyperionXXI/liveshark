use std::fs;
use std::path::Path;

use liveshark_core::{Report, analyze_pcap_file};

fn run_golden(dir: &str) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    let input = root.join(dir).join("input.pcapng");
    let expected_path = root.join(dir).join("expected_report.json");

    let expected_json = fs::read_to_string(&expected_path).expect("read expected_report.json");
    let expected: Report = serde_json::from_str(&expected_json).expect("parse expected report");

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
fn golden_sacn_burst() {
    run_golden("tests/golden/sacn_burst");
}

#[test]
fn golden_sacn_gap() {
    run_golden("tests/golden/sacn_gap");
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

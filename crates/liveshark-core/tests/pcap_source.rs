use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use liveshark_core::{PacketSource, PcapFileSource, SourceError};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[test]
fn pcap_source_reads_packets_from_fixture() {
    let path = repo_root()
        .join("tests")
        .join("golden")
        .join("artnet")
        .join("input.pcapng");
    let mut source = PcapFileSource::open(&path).unwrap();

    let mut packets = 0;
    while let Some(_event) = source.next_packet().unwrap() {
        packets += 1;
    }

    assert!(packets > 0);
}

#[test]
fn pcap_source_rejects_truncated_file() {
    let mut path = std::env::temp_dir();
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    path.push(format!("liveshark_truncated_{unique}.pcapng"));

    fs::write(&path, [0x0a, 0x0d, 0x0d]).unwrap();
    let err = match PcapFileSource::open(&path) {
        Ok(_) => panic!("expected truncated file to be rejected"),
        Err(err) => err,
    };
    let _ = fs::remove_file(&path);

    assert!(matches!(err, SourceError::Io(_)));
}

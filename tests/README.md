Synthetic fixtures

To regenerate deterministic synthetic PCAPNG files used by golden tests:

  cargo run -p liveshark-core --bin pcapng_fixtures

This updates only the fixture inputs under tests/golden/* and does not change expected JSON.

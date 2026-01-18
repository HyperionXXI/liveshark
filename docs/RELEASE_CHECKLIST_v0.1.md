# Release Checklist v0.1

Short checklist to close v0.1 without adding features.

## Local CI commands
- `cargo fmt --all`
- `cargo test -p liveshark-core --lib`
- `cargo test -p liveshark-core --test golden`
- `cargo test -p liveshark-cli --test cli`
- `cargo clippy -p liveshark-core --all-targets -- -D warnings`
- `cargo clippy -p liveshark-cli --all-targets -- -D warnings`

## Windows verification
- Run `cargo test -p liveshark-cli --test cli` on Windows.
- Manually smoke `liveshark pcap follow capture.pcapng --report report.json`.

## Docs
- `cargo test -p liveshark-core --doc`
- `cargo doc -p liveshark-core --no-deps`
- `cargo doc -p liveshark-cli --no-deps --bins`
- Ensure no ` ```ignore` doctests remain.

## Consumer contract
- Read `docs/consumer-contract.md` and confirm: absence != zero, loss only when sequence exists, unknown fields ignored.

## Tag + GitHub Release
- `git tag v0.1.0`
- `git push origin v0.1.0`
- Create GitHub Release `v0.1.0` with short notes.
- Attach Windows binary if available.

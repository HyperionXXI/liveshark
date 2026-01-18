# LiveShark

**LiveShark** is a *post-mortem* network analyzer for show control.

It analyzes **PCAP/PCAPNG** captures and turns Art-Net / sACN traffic into **DMX frame reconstruction**, **automatic conflict detection** (double emitters), and **reproducible reports**.

> Status: **v0.1 specification complete / core + follow implemented; ongoing hardening**.

## Quick overview

**What LiveShark does:**
- Analyze PCAP/PCAPNG captures (Art-Net, sACN)
- Reconstruct DMX frames (512 slots per universe)
- Detect conflicts (double emitters)
- Generate versioned, reproducible JSON reports

**What LiveShark is not:**
- Not a Wireshark replacement (domain-specific analyzer)
- Not a live capture tool (v0.1 is offline post-mortem)
- Not a DMX transmitter (passive analysis only)

**Next steps:** see the Roadmap section below.

## Why LiveShark?

- **Wireshark**: excellent packet view, but no DMX *frame* reconstruction or domain metrics.
- **sACNView / ArtNetominator**: great live monitoring, but no offline PCAP post-mortem.
- LiveShark bridges the gap: **offline + DMX frames + conflicts + reports**.

## Documentation / Specification

- Printable specification sources (authoritative): `spec/en/LiveShark_Spec.tex`
- Consumer contract guide (JSON): `docs/consumer-contract.md`
- Documentation build instructions: `docs/README.md`
- Rust architecture rules (normative): `docs/RUST_ARCHITECTURE.md`

The project specification (requirements) is written in LaTeX (`.tex`); see "Build the PDFs" below to compile it.

## Usage modes

- **Offline analysis (post-mortem):** analyze a completed PCAP/PCAPNG capture file.
- **Follow mode:** near-real-time analysis of a capture file that is still being written by an external tool.
- **Native live capture (future, optional):** a possible future objective, not required for the initial milestone.

Follow mode rewrites a full report while a capture file grows:
`liveshark pcap follow capture.pcapng --report report.json`

Offline-first is an implementation strategy (robustness, reproducibility), not a product limitation.
LiveShark also targets reliable network diagnostics for small/medium show rigs (wired/wireless), focusing on loss, jitter, and burst patterns with probable-cause hints when possible.

## Quickstart v0.1

Analyze a capture and write a report:
`liveshark pcap analyze capture.pcapng --report report.json`

Follow a growing capture and rewrite the report:
`liveshark pcap follow capture.pcapng --report report.json`

Interpretation notes:
- Absence != zero (optional fields are omitted when not computable).
- Loss metrics are only reported when sequence numbers exist (sACN).
- Output lists are sorted for deterministic reports.

## Report Viewer (GUI)

See `gui/report-viewer/` for a zero-dependency, offline HTML viewer of `report.json`.
Contract reminders: absence != zero, loss only when sequence exists (sACN), and JSON lists are deterministic.
Note: when opened via file://, Reload can only re-read the last selected file object.
Large reports may be slow to render in the table view.

## Build the PDFs (for non-developers)

The specs are compiled directly from the `.tex` sources (no external diagram tools required).

Option A -- MiKTeX GUI (Windows, no terminal required)
- Open `spec/en/LiveShark_Spec.tex` in the MiKTeX/TeXworks GUI.
- Use XeLaTeX and compile to PDF.

Note: this does not require Perl; `latexmk` does.

Option B -- Make (if available)
```bash
make pdf
```

Option C -- direct (requires Perl for `latexmk` on Windows)
```bash
latexmk -xelatex -interaction=nonstopmode -halt-on-error spec/en/LiveShark_Spec.tex
```

Outputs:
- `spec/en/LiveShark_Spec.pdf`
Note: PDFs are generated artifacts and should not be committed to the repository.

## Roadmap (high level)

- v0.1: offline PCAP analysis + Art-Net/sACN decoding + DMX frames + conflict detector + JSON reports
- v0.2: GUI offline (timeline + diff viewer)
- v0.3+: live capture (optional)

## Licenses

Code: MIT OR Apache-2.0 (see `LICENSE-MIT` and `LICENSE-APACHE`).
Docs/specs: CC-BY-4.0 (see `LICENSE-CC-BY-4.0`).

## Toolchain

PDFs are built with XeLaTeX/latexmk only (TikZ for diagrams). No external diagram tools are required.
Rust toolchain: edition 2024, MSRV 1.85 (CI validates stable + MSRV).

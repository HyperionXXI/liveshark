# LiveShark

**LiveShark** is a *post-mortem* network analyzer for show control.

It analyzes **PCAP/PCAPNG** captures and turns Art-Net / sACN traffic into **DMX frame reconstruction**, **automatic conflict detection** (double emitters), and **reproducible reports**.

> Status: **BOOTSTRAP / not yet implemented** -- repository currently contains specification and project scaffolding.

## Why LiveShark?

- **Wireshark**: excellent packet view, but no DMX *frame* reconstruction or domain metrics.
- **sACNView / ArtNetominator**: great live monitoring, but no offline PCAP post-mortem.
- LiveShark bridges the gap: **offline + DMX frames + conflicts + reports**.

## Documentation / Specification

- Printable specification sources (authoritative): `spec/en/LiveShark_Spec.tex`
- French best-effort translation: `spec/fr/LiveShark_Spec.tex`
- Documentation build instructions: `docs/README.md`
The project specification (requirements) is written in LaTeX (`.tex`); see "Build the PDFs" below to compile it.

## Usage modes

- **Offline analysis (post-mortem):** analyze a completed PCAP/PCAPNG capture file.
- **Follow mode (planned):** near-real-time analysis of a capture file that is still being written by an external tool.
- **Native live capture (future, optional):** a possible future objective, not required for the initial milestone.

Offline-first is an implementation strategy (robustness, reproducibility), not a product limitation.
LiveShark also targets reliable network diagnostics for small/medium show rigs (wired/wireless), focusing on loss, jitter, and burst patterns with probable-cause hints when possible.

## Build the PDFs (for non-developers)

The specs are compiled directly from the `.tex` sources (no external diagram tools required).

Option A -- MiKTeX GUI (Windows, no terminal required)
- Open `spec/en/LiveShark_Spec.tex` or `spec/fr/LiveShark_Spec.tex` in the MiKTeX/TeXworks GUI.
- Use XeLaTeX and compile to PDF.

Option B -- Make (if available)
```bash
make pdf
```

Option C -- direct (works on Windows with MiKTeX + Perl)
```bash
latexmk -xelatex -interaction=nonstopmode -halt-on-error spec/en/LiveShark_Spec.tex
latexmk -xelatex -interaction=nonstopmode -halt-on-error spec/fr/LiveShark_Spec.tex
```

Outputs:
- `spec/en/LiveShark_Spec.pdf`
- `spec/fr/LiveShark_Spec.pdf`
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

## Languages

- **EN** is the reference version for specs and contracts.
- **FR** is a translation to ease review and analysis.

If there is a mismatch, EN prevails until explicitly validated otherwise.

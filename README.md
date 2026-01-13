# 🦈 LiveShark

**LiveShark** is a *post‑mortem* network analyzer for show control.

It analyzes **PCAP/PCAPNG** captures and turns Art‑Net / sACN traffic into **DMX frame reconstruction**, **automatic conflict detection** (double emitters), and **reproducible reports**.

> Status: **BOOTSTRAP / not yet implemented** — repository currently contains specification and project scaffolding.

## Why LiveShark?

- **Wireshark**: excellent packet view, but no DMX *frame* reconstruction or domain metrics.
- **sACNView / ArtNetominator**: great live monitoring, but no offline PCAP post‑mortem.
- LiveShark bridges the gap: **offline + DMX frames + conflicts + reports**.

## Documentation / Specification

- Printable specification sources (authoritative): `spec/en/LiveShark_Spec.tex`
- French best‑effort translation: `spec/fr/LiveShark_Spec.tex`
- Documentation build instructions: `docs/README.md`

## Build the PDFs (for non‑developers)

```bash
make pdf
```

Outputs:
- `spec/en/LiveShark_Spec.pdf`
- `spec/fr/LiveShark_Spec.pdf`

## Roadmap (high level)

- v0.1: offline PCAP analysis + Art‑Net/sACN decoding + DMX frames + conflict detector + JSON reports
- v0.2: GUI offline (timeline + diff viewer)
- v0.3+: live capture (optional)

## License

TBD (code) — documentation license file included as placeholder.

## Toolchain

PDFs are built with XeLaTeX/latexmk only (TikZ for diagrams). No external diagram tools are required.

## Languages

- **EN** is the reference version for specs and contracts.
- **FR** is a translation to ease review and analysis.

If there is a mismatch, EN prevails until explicitly validated otherwise.

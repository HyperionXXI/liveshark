# LiveShark Documentation (spec-first)

This repository provides a **printable PDF spec document** for non-developers, while keeping a **single editable source of truth**.

What is authoritative?
- **Authoritative source (normative):** `spec/en/LiveShark_Spec.tex`
- **French translation:** `spec/fr/LiveShark_Spec.tex` (informational, may lag)
- **PDF files:** build artifacts generated from `.tex` sources. They are provided for convenience and **must not** be treated as the source of truth.
- **Rust architecture rules (normative):** `docs/RUST_ARCHITECTURE.md`

Build the PDFs
Option A -- MiKTeX GUI (Windows, no terminal required)
- Open `spec/en/LiveShark_Spec.tex` or `spec/fr/LiveShark_Spec.tex` in the MiKTeX/TeXworks GUI.
- Use XeLaTeX and compile to PDF.
Note: this does not require Perl; `latexmk` does.

CI builds
- GitHub Actions builds the PDFs and injects the git commit hash into the footer.
Local builds
- Local builds may display a "local" marker in the footer if no CI commit hash is available.

Option B -- Make (if available)
```bash
make pdf
```

Option C -- direct (requires Perl for `latexmk` on Windows)
```bash
latexmk -xelatex -interaction=nonstopmode -halt-on-error spec/en/LiveShark_Spec.tex
latexmk -xelatex -interaction=nonstopmode -halt-on-error spec/fr/LiveShark_Spec.tex
```

The specs are compiled directly from the `.tex` sources (no external diagram tools required).

Outputs:
- `spec/en/LiveShark_Spec.pdf`
- `spec/fr/LiveShark_Spec.pdf`

Mini-glossary
- **Offline analysis / post-mortem:** analysis of a completed capture file.
- **Follow mode:** near-real-time analysis of a capture file that is still being written.
- **Near-real-time:** low-latency analysis driven by file growth, without native capture.
Note: PDFs are generated artifacts and should not be committed to the repository.

Notes
- The visual style is intentionally simple and professional (no gimmicks).
- Hyperlink borders are disabled (no red boxes).
- Figures are constrained to the page width.

Golden tests
- Format: `tests/golden/<name>/{input.pcapng, expected_report.json}`.
- Add a new folder and update `crates/liveshark-core/tests/golden.rs` if needed.

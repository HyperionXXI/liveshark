# LiveShark Documentation (spec-first)

EN

This repository provides a **printable PDF specification** for non-developers, while keeping a **single editable source of truth**.

What is authoritative?
- **Authoritative source (normative):** `spec/en/LiveShark_Spec.tex`
- **French translation:** `spec/fr/LiveShark_Spec.tex` (best-effort, may lag)
- **PDF files:** build artifacts generated from `.tex` sources. They are provided for convenience and **must not** be treated as the source of truth.
- **Rust architecture rules (normative):** `docs/RUST_ARCHITECTURE.md`

Build the PDFs
Option A -- MiKTeX GUI (Windows, no terminal required)
- Open `spec/en/LiveShark_Spec.tex` or `spec/fr/LiveShark_Spec.tex` in the MiKTeX/TeXworks GUI.
- Use XeLaTeX and compile to PDF.
Note: this does not require Perl; `latexmk` does.

CI builds
- GitHub Actions builds the PDFs and injects the git commit hash into the footer.

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

FR

Ce depot fournit une **specification PDF imprimable** pour les non-developpeurs, avec **une seule source editable**.

Quelle est la reference ?
- **Source normative (fait foi) :** `spec/en/LiveShark_Spec.tex`
- **Traduction francaise :** `spec/fr/LiveShark_Spec.tex` (best-effort, peut etre en retard)
- **Fichiers PDF :** artefacts generes depuis les `.tex`. Ils sont fournis par confort et **ne sont pas la source de verite**.
- **Regles d'architecture Rust (normatif) :** `docs/RUST_ARCHITECTURE.fr.md`

Generer les PDF
Option A -- MiKTeX GUI (Windows, sans terminal)
- Ouvrir `spec/en/LiveShark_Spec.tex` ou `spec/fr/LiveShark_Spec.tex` dans l'interface MiKTeX/TeXworks.
- Utiliser XeLaTeX et compiler en PDF.
Note : cela ne nécessite pas Perl ; `latexmk` oui.

Builds CI
- GitHub Actions compile les PDF et injecte le hash du commit dans le pied de page.

Option B -- Make (si disponible)
```bash
make pdf
```

Option C -- direct (nécessite Perl pour `latexmk` sous Windows)
```bash
latexmk -xelatex -interaction=nonstopmode -halt-on-error spec/en/LiveShark_Spec.tex
latexmk -xelatex -interaction=nonstopmode -halt-on-error spec/fr/LiveShark_Spec.tex
```

Les specs sont compilees directement depuis les sources `.tex` (aucun outil de diagramme externe requis).

Sorties :
- `spec/en/LiveShark_Spec.pdf`
- `spec/fr/LiveShark_Spec.pdf`

Mini-glossaire
- **Analyse hors ligne / a posteriori :** analyse d'un fichier de capture terminé.
- **Mode suivi :** analyse en quasi temps reel d'un fichier de capture en cours d'ecriture.
- **Quasi temps reel :** faible latence liee a la croissance du fichier, sans capture native.
Note : les PDF sont des artefacts générés et ne doivent pas être committés dans le dépôt.

Notes
- Le style visuel est volontairement simple et professionnel (sans effets).
- Les bordures de liens sont desactivees.
- Les figures sont contraintes a la largeur de page.

Tests golden
- Format : `tests/golden/<nom>/{input.pcapng, expected_report.json}`.
- Ajouter un nouveau dossier et mettre a jour `crates/liveshark-core/tests/golden.rs` si besoin.

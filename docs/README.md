# LiveShark — Documentation base (spec-first)

This repository skeleton provides a **printable PDF specification** for non-developers, while keeping a **single editable source of truth**.

## What is authoritative?

- **Authoritative source (normative):** `spec/en/LiveShark_Spec.tex`
- **French translation:** `spec/fr/LiveShark_Spec.tex` (best-effort, may lag)
- **PDF files:** build artifacts generated from `.tex` sources. They are provided for convenience and **must not** be treated as the source of truth.

## Build the PDFs

### Option A — Make (recommended)
```bash
make pdf
```

### Option B — direct (requires latexmk)
```bash
latexmk -xelatex -interaction=nonstopmode -halt-on-error spec/en/LiveShark_Spec.tex
latexmk -xelatex -interaction=nonstopmode -halt-on-error spec/fr/LiveShark_Spec.tex
```

Outputs:
- `spec/en/LiveShark_Spec.pdf`
- `spec/fr/LiveShark_Spec.pdf`

## Notes
- The visual style is intentionally **simple and professional** (no gimmicks).
- Hyperlink borders are disabled (no red boxes).
- Figures are constrained to the page width.

## Toolchain (kept minimal)

Pour générer les PDF, une distribution LaTeX standard avec **XeLaTeX** et **latexmk** suffit.
Les diagrammes et formules sont réalisés **dans LaTeX** (TikZ + maths) : aucun outil externe n’est requis.


## Langues

- **Anglais (EN)** : version de **référence** pour le projet (terminologie, IDs d’exigences, contrats).
- **Français (FR)** : traduction destinée à faciliter la relecture et l’analyse.  
  En cas de divergence, la version EN fait foi (jusqu’à validation explicite contraire).

> Objectif : garder les deux versions alignées, mais sans bloquer le développement si la traduction prend du retard.


## Capture (v0.1)

- LiveShark analyse des fichiers **PCAP/PCAPNG**.
- La capture peut être réalisée par des outils standards (tcpdump/dumpcap). **Wireshark GUI n’est pas requis.**

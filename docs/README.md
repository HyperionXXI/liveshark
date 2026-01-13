# LiveShark Documentation (spec-first)

EN

This repository provides a **printable PDF specification** for non-developers, while keeping a **single editable source of truth**.

What is authoritative?
- **Authoritative source (normative):** `spec/en/LiveShark_Spec.tex`
- **French translation:** `spec/fr/LiveShark_Spec.tex` (best-effort, may lag)
- **PDF files:** build artifacts generated from `.tex` sources. They are provided for convenience and **must not** be treated as the source of truth.

Build the PDFs
Option A -- Make (if available)
```bash
make pdf
```

Option B -- direct (works on Windows with MiKTeX)
```bash
latexmk -xelatex -interaction=nonstopmode -halt-on-error spec/en/LiveShark_Spec.tex
latexmk -xelatex -interaction=nonstopmode -halt-on-error spec/fr/LiveShark_Spec.tex
```

The specs are compiled directly from the `.tex` sources (no external diagram tools required).

Outputs:
- `spec/en/LiveShark_Spec.pdf`
- `spec/fr/LiveShark_Spec.pdf`

Notes
- The visual style is intentionally simple and professional (no gimmicks).
- Hyperlink borders are disabled (no red boxes).
- Figures are constrained to the page width.

FR

Ce depot fournit une **specification PDF imprimable** pour les non-developpeurs, avec **une seule source editable**.

Quelle est la reference ?
- **Source normative (fait foi) :** `spec/en/LiveShark_Spec.tex`
- **Traduction francaise :** `spec/fr/LiveShark_Spec.tex` (best-effort, peut etre en retard)
- **Fichiers PDF :** artefacts generes depuis les `.tex`. Ils sont fournis par confort et **ne sont pas la source de verite**.

Generer les PDF
Option A -- Make (si disponible)
```bash
make pdf
```

Option B -- direct (fonctionne sous Windows avec MiKTeX)
```bash
latexmk -xelatex -interaction=nonstopmode -halt-on-error spec/en/LiveShark_Spec.tex
latexmk -xelatex -interaction=nonstopmode -halt-on-error spec/fr/LiveShark_Spec.tex
```

Les specs sont compilees directement depuis les sources `.tex` (aucun outil de diagramme externe requis).

Sorties :
- `spec/en/LiveShark_Spec.pdf`
- `spec/fr/LiveShark_Spec.pdf`

Notes
- Le style visuel est volontairement simple et professionnel (sans effets).
- Les bordures de liens sont desactivees.
- Les figures sont contraintes a la largeur de page.

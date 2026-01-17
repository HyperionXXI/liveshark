# Documentation LiveShark (spécification d'abord)

Ce dépôt fournit une **spécification PDF imprimable** pour les non-développeurs, avec **une seule source éditable**.

Quelle est la référence ?
- **Source normative (fait foi) :** `spec/en/LiveShark_Spec.tex`
- **Traduction française :** `spec/fr/LiveShark_Spec.tex` (traduction indicative, peut être en retard)
- **Contrat de consommation JSON :** `docs/fr/consumer-contract.md`
- **Fichiers PDF :** artefacts générés depuis les `.tex`. Ils sont fournis par confort et **ne sont pas la source de vérité**.
- **Règles d'architecture Rust (fait foi) :** `docs/RUST_ARCHITECTURE.md`
- **Traduction française des règles Rust :** `docs/RUST_ARCHITECTURE.fr.md` (traduction indicative)

Générer les PDF
Option A -- MiKTeX GUI (Windows, sans terminal)
- Ouvrir `spec/en/LiveShark_Spec.tex` ou `spec/fr/LiveShark_Spec.tex` dans l'interface MiKTeX/TeXworks.
- Utiliser XeLaTeX et compiler en PDF.
Note : cela ne nécessite pas Perl ; `latexmk` oui.

Intégration continue
- GitHub Actions compile les PDF et injecte l'empreinte de révision Git dans le pied de page.

Option B -- Make (si disponible)
```bash
make pdf
```

Option C -- direct (nécessite Perl pour `latexmk` sous Windows)
```bash
latexmk -xelatex -interaction=nonstopmode -halt-on-error spec/en/LiveShark_Spec.tex
latexmk -xelatex -interaction=nonstopmode -halt-on-error spec/fr/LiveShark_Spec.tex
```

Les spécifications sont compilées directement depuis les sources `.tex` (aucun outil de diagramme externe requis).

Sorties :
- `spec/en/LiveShark_Spec.pdf`
- `spec/fr/LiveShark_Spec.pdf`

Mini-glossaire
- **Analyse hors ligne / a posteriori :** analyse d'un fichier de capture terminé.
- **Mode suivi :** analyse en quasi temps réel d'un fichier de capture en cours d'écriture.
- **Quasi temps réel :** faible latence liée à la croissance du fichier, sans capture native.
Note : les PDF sont des artefacts générés et ne doivent pas être versionnés dans le dépôt.

Notes
- Le style visuel est volontairement simple et professionnel (sans effets).
- Les bordures de liens sont désactivées.
- Les figures sont contraintes à la largeur de page.

Tests golden
- Format : `tests/golden/<nom>/{input.pcapng, expected_report.json}`.
- Ajouter un nouveau dossier et mettre à jour `crates/liveshark-core/tests/golden.rs` si besoin.

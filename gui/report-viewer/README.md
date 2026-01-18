# LiveShark Report Viewer (v0.1)

A small zero-dependency HTML/CSS/JS viewer to inspect a LiveShark `report.json`.
This viewer is local/offline only: no network access, no dependencies.

## Usage
1. Open `index.html` in a modern browser (Chrome / Edge / Firefox).
2. Click **Open report.json** and select a LiveShark report file (drag and drop also works).
3. Browse **Universes / Flows / Conflicts / Compliance**, sort columns, and use the text filter.

## Interpretation notes (contract)
- **Absence != zero**: optional metrics are **omitted** when not computable and displayed as **N/A**.
- **Loss metrics** are reported **only** when protocol sequence numbers exist (e.g. **sACN**). No loss is inferred for Art-Net.
- **Determinism**: report lists are sorted deterministically in JSON; the UI may re-sort locally for display.

## Known limitations
- Browser file:// security can limit automatic reload; use the Reload button when needed.
- Large reports may be slow to render in the table view.

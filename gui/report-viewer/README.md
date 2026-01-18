# LiveShark Report Viewer (v0.1)

A small zero-dependency HTML/CSS/JS viewer to inspect a LiveShark `report.json`.

## Usage
1. Open `index.html` in a modern browser (Chrome / Edge / Firefox).
2. Click **Open report.json** and select a LiveShark report file.
3. Browse **Universes / Flows / Conflicts / Compliance**, sort columns, and use the text filter.

## Interpretation notes (contract)
- **Absence ≠ zero**: optional metrics are **omitted** when not computable and displayed as **N/A**.
- **Loss metrics** are reported **only** when protocol sequence numbers exist (e.g. **sACN**). No loss is inferred for Art-Net.
- **Determinism**: report lists are sorted deterministically in JSON; the UI may re-sort locally for display.

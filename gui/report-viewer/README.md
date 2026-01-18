# LiveShark Report Viewer (v0.1.1)

A small zero-dependency HTML/CSS/JS viewer to inspect a LiveShark `report.json`.
This viewer is local/offline only: no network access, no dependencies.

## Usage
1. Open `index.html` in a modern browser (Chrome / Edge / Firefox).
2. Drag and drop a LiveShark report, or click **Open report.json**.
3. Use tabs, sorting, and filter to inspect data; click a row for details.

## Contract notes
- Optional fields are omitted when not computable (absence != zero).
- Loss metrics exist only when sequence numbers exist (for example, sACN); never inferred for Art-Net.
- Lists are sorted deterministically in the report.

## Limitations
- Browser file:// security means Reload only re-reads the last selected File object.
- Large reports may be slow to render in the table view.

## QA checklist
See `docs/VIEWER_QA.md` after any GUI change.

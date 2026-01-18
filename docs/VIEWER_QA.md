# Viewer QA Checklist

Use this quick checklist after any Report Viewer GUI change.

- Load a valid report.json; table renders and clicking a row populates Details.
- Sort: header click toggles asc/desc with a visible ▲/▼ indicator; default order is unchanged until first sort.
- Filter: matches across all visible columns and shows a "No results" state when empty.
- Truncation: long cells are truncated and the full value is available via tooltip.
- Details: scroll works, Raw JSON is monospace, Copy JSON works (clipboard + fallback).
- Invalid JSON: an error banner appears and the last valid report remains visible.
- Optional fields render as "N/A" (absence != zero).

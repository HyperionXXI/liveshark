# Viewer Validation Procedure

Use this procedure to validate the Report Viewer on real reports without
committing large artifacts.

## Baseline sanity check (quick)

Open `gui/report-viewer/index.html` and load a few golden reports:

- `tests/golden/*/expected_report.json`

Confirm:
- Table renders, row click populates Details.
- Sort toggles asc/desc with ▲/▼.
- Filter matches across visible columns and shows "No results" when empty.
- Error banner appears on invalid JSON.

## Real-world check (small/medium/large)

Generate 2–3 reports from real captures and load them in the viewer.
Use the CLI in analyze mode (preferred spelling: `analyze`):

```
liveshark pcap analyze capture_small.pcapng --report gui/report-viewer/fixtures/report_small.json
liveshark pcap analyze capture_medium.pcapng --report gui/report-viewer/fixtures/report_medium.json
liveshark pcap analyze capture_large.pcapng --report gui/report-viewer/fixtures/report_large.json
```

Confirm:
- Sort and filter remain responsive.
- Details panel is readable and scrollable.
- Copy JSON works (clipboard + fallback).
- Long values are truncated in the table with full tooltips.

## Notes

- Do not commit the generated JSON files.
- If you want a placeholder directory, use `gui/report-viewer/fixtures/.gitkeep`.

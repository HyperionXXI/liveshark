# Release Notes v0.2.0

## ✨ Major Features

### Timeline Visualization & Interactive Exploration
LiveShark now features an interactive timeline view for exploring universe events and conflicts:

- **SVG Timeline Display**: Visual representation of universe activity (first_seen → last_seen)
  - Universe bars color-coded by protocol (sACN=red, Art-Net=blue)
  - Conflict markers (orange triangles) show exact detection time
  - Time axis with formatted labels and responsive scaling

- **Click-to-Filter Interaction**: 
  - Click universe bar → filters table to that universe+protocol
  - Click conflict marker → switches to conflicts tab, highlights matching row
  - Temporary highlighting (2s fade) with golden background and outline
  - Clear button or ESC key to remove filter

- **Hover Preview** (desktop):
  - Mouse over → row highlights without filtering
  - Disabled on touch devices (mobile-friendly fallback)

- **Enhanced Filter Status**:
  - Shows match count: "Filtered: Universe 12 (sACN) — 3 rows"
  - Plural-aware row counter

### Schema Additions (Backward Compatible)

Added temporal fields for precise timeline support:
- `UniverseSummary.first_seen`, `last_seen` (float, seconds from capture start)
- `ConflictSummary.first_seen` (float, when overlap detected)
- All fields optional with `skip_serializing_if` for full backward compatibility
- Existing reports without temporal data display timeline as hidden (safe degradation)

### Accessibility & Mobile

- **Keyboard Navigation**: SVG elements (universe bars, conflict markers) now fully keyboard accessible
  - `tabindex=0` enables Tab navigation
  - `role=button` + `aria-label` for screen readers
  - Enter/Space keys trigger same action as click
  
- **Touch Device Support**: Smart hover detection
  - `matchMedia("(hover: none)")` detects touch devices
  - Hover-preview disabled on touch (prevents sticky highlights)
  - Click/tap behavior works on all devices

### UX & Stability Improvements

- **Conflict Key Stability**: Changed from `universe:proto:sources:first_seen` to `universe:proto:sources`
  - Removes dependency on timestamp (may be missing in incomplete data)
  - Uses sorted sources for deterministic matching
  - Prevents failures when temporal data varies by source

- **Enhanced Feedback**:
  - Warning toast if conflict row not found ("Conflict row not found — may have been filtered")
  - Notification severity levels (info=blue, warning=orange)
  - Clearer visibility of filter impact with row counts

## 🛠️ Technical

### Code Quality
- ✅ 112 tests passing (73 unit + 22 CLI + 18 golden + 2 source)
- ✅ `cargo fmt` clean
- ✅ 0 clippy warnings
- ✅ Backward compatible (no schema breaking changes)

### GUI Enhancements
- `gui/report-viewer/app.js`: +90 lines
  - Timeline extraction and SVG rendering
  - Interactive filter/focus handlers
  - Touch device detection
  - Accessibility attributes
  - Enhanced notifications

- `gui/report-viewer/style.css`: +40 lines  
  - Timeline styling (bars, markers, axis)
  - Notification severity colors
  - Filter status display

- `gui/report-viewer/index.html`: Timeline section added (already included in v0.1.2+)

### Rust Core (Minimal Changes)
- `crates/liveshark-core/src/lib.rs`: Schema fields added
- `crates/liveshark-core/src/analysis/universes.rs`: Temporal data population from packet timestamps

## 📊 Data Format

### Example with Temporal Data
```json
{
  "universes": [
    {
      "universe": 1,
      "proto": "sacn",
      "first_seen": 0.001234,
      "last_seen": 125.456789,
      ...
    }
  ],
  "conflicts": [
    {
      "universe": 1,
      "proto": "artnet",
      "first_seen": 45.123456,
      ...
    }
  ]
}
```

All temporal fields are optional. Reports without them degrade gracefully (timeline hidden).

## 🚀 Deployment

- **No breaking changes**: Existing tools, libraries, and reports continue to work
- **Optional enhancement**: Timeline visible only if temporal data present
- **Browser support**: Modern browsers (Chrome, Firefox, Safari, Edge) with SVG support
- **Mobile**: Full functionality on touch devices with adapted hover behavior

## 📝 Known Limitations

- Timeline hidden if no temporal data in report (reports generated before analysis updated)
- Touch devices don't show hover-preview (click-to-filter still available)
- Very large reports (1000+ rows) may have slower table operations (optimization for v0.3)

## 🔄 Migration Guide

No migration needed. v0.2.0 is fully backward compatible:
- Old reports work with v0.2.0 viewer (timeline hidden)
- New data with temporal fields automatically visualize timeline
- API consumers: optional `first_seen`/`last_seen` fields can be ignored

## 📦 Contents

- **Binary**: liveshark-cli with updated analysis
- **Library**: liveshark-core with schema v0.2
- **GUI**: Enhanced report-viewer with timeline + polish
- **Docs**: Updated specification + release checklist
- **Tests**: All 112 tests passing

---

**Version**: v0.2.0  
**Release Date**: 2026-01-20  
**Status**: Production Ready  
**Backward Compatibility**: ✅ Full

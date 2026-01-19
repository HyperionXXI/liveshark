# GUI Development Plan: v0.2.0 Timeline & Schema

## Overview
**Objective:** Render v0.2 additive schema fields (source_id, proto) + implement timeline visualization.

**Branch:** `feature/gui-v02-timeline-schema`

**Timeline estimate:** 1-2 weeks (depending on HTML/CSS/JS complexity)

---

## Phase 1: Schema Field Rendering (Foundation)

### 1.1 Render `source_id` in Universe Summary
**File:** `gui/report-viewer/app.js`

**Current behavior:**
- Universe table shows: Universe, Protocol, FPS, Jitter, Loss, Burst, Gap
- Source table shows: Source ID, FPS, Jitter, Loss

**Goal:**
- Add `source_id` column to universe sources breakdown
- Format: "ip:port" (artnet) or "cid" (sacn)
- Show alongside existing "Source ID" in source table

**Changes:**
1. Parse JSON: `universes[i].sources[j].source_id` if present
2. Update HTML template: Add column header "Source"
3. CSS: Style source_id column (monospace font, light background)

### 1.2 Render `proto` in Conflict Summary
**File:** `gui/report-viewer/app.js`

**Current behavior:**
- Conflict table shows: Universe, Conflict Type, Sources

**Goal:**
- Add `proto` column showing protocol name
- Format: "artnet" or "sacn"
- Clarify which protocol conflicted

**Changes:**
1. Parse JSON: `conflicts[i].proto` if present
2. Update HTML: Add "Protocol" column in conflict table
3. CSS: Color-code by protocol (artnet=blue, sacn=red)

---

## Phase 2: Timeline Visualization (Feature)

### 2.1 Add Timeline UI Component
**File:** `gui/report-viewer/index.html`, `app.js`, `style.css`

**Goal:**
- Add horizontal timeline showing capture duration
- Mark events: flows, conflicts, sources appearing/disappearing

**HTML Structure:**
```html
<div id="timeline-container">
  <svg id="timeline" width="100%" height="150px"></svg>
  <div id="timeline-legend">
    <span class="legend-flow">Flow</span>
    <span class="legend-conflict">Conflict</span>
  </div>
</div>
```

**Data needed:**
- `universes[i].first_seen` (when first universe packet arrived)
- `universes[i].last_seen` (when last universe packet arrived)
- `conflicts[i].first_seen` (when conflict first detected)

**Note:** Schema update required (see Phase 3 below)

### 2.2 Timeline Rendering Logic
**Algorithm:**
1. Calculate report duration: max(last_seen) - min(first_seen)
2. For each universe: Draw horizontal bar from first_seen to last_seen
3. For each conflict: Draw marker at first_seen time
4. Y-axis: Universe numbers; X-axis: time (linear scale)
5. Tooltip: Show timestamps on hover

---

## Phase 3: Schema Extension (Backend)

### 3.1 Add Temporal Fields
**Files:** `crates/liveshark-core/src/lib.rs`

**Goal:** Extend schema with optional temporal tracking

**Changes:**
```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UniverseSummary {
    // ... existing fields
    pub universe: u16,
    pub protocol: String,
    pub fps: Option<f64>,
    // NEW FIELDS:
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<f64>,  // seconds since capture start
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<f64>,   // seconds since capture start
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConflictSummary {
    // ... existing fields
    // NEW FIELD:
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<f64>,  // when conflict was first detected
}
```

**Backward compatibility:**
- Fields optional (skip_serializing_if = "Option::is_none")
- report_version remains 1
- Consumers can ignore if not present

### 3.2 Populate Temporal Fields in Analysis
**File:** `crates/liveshark-core/src/analysis/mod.rs`

**Changes:**
1. Track first/last packet timestamp for each universe
2. Track first conflict detection timestamp
3. Store in respective Summary structs during analysis

**Test coverage:**
- Golden tests: Regenerate with new fields populated
- Verify backward compatibility: Compare with v0.1.2 golden outputs (ignore new fields)

---

## Phase 4: Testing & Quality

### 4.1 Unit Tests
**Location:** `crates/liveshark-core/src/analysis/tests/`

**Tests needed:**
- first_seen/last_seen correctly populated for artnet
- first_seen/last_seen correctly populated for sacn
- Conflict first_seen set at correct timestamp
- Backward compatibility: old consumers ignore new fields

### 4.2 Golden Test Regeneration
**Action:**
```bash
cargo test --all -- --ignored --exact regenerate_golden_tests
```

**Files to update:**
- tests/golden/*/expected_report.json (all 13 fixtures)

**Verification:**
- All 112 tests passing
- No clippy warnings
- Spec compliance verified

### 4.3 GUI Testing
**Files:** `gui/report-viewer/` HTML/CSS/JS

**Manual tests:**
1. Load v0.1.2 reports (no new fields) → GUI doesn't crash
2. Load v0.2 reports (with new fields) → GUI renders source_id, proto correctly
3. Timeline renders for various capture durations (1s, 1min, 1hour)
4. Responsive design: works on mobile (small timeline window)

---

## Phase 5: Documentation & Release

### 5.1 Update Specifications
**Files:** `spec/en/LiveShark_Spec.tex`, `spec/fr/LiveShark_Spec.tex`

**Changes:**
- Document first_seen, last_seen in schema appendix
- Add examples in JSON reference section
- Note: These fields are OPTIONAL and for timeline visualization

### 5.2 Update README
**File:** `README.md`

**Changes:**
- Link to GUI v0.2.0 features in Feature section
- Screenshot of timeline visualization
- Note about v0.2.0 schema (additive from v0.1.2)

### 5.3 Release v0.2.0
**Checklist:**
- [ ] Code: All tests passing, 0 clippy warnings
- [ ] Specs: EN/FR compiled, temporal fields documented
- [ ] Binary: Release built, smoke tested
- [ ] Release notes: Created & published
- [ ] GitHub Release: Created with timeline screenshot
- [ ] Tag: v0.2.0 created and pushed

---

## Implementation Order

1. **Phase 1.1** → Render source_id (low-risk, schema already supports)
2. **Phase 1.2** → Render proto (low-risk, schema already supports)
3. **Phase 3.1** → Add temporal fields to schema (backend)
4. **Phase 3.2** → Populate temporal fields in analysis
5. **Phase 4.1 & 4.2** → Test & regenerate goldens
6. **Phase 2.1 & 2.2** → Implement timeline UI
7. **Phase 4.3** → GUI testing
8. **Phase 5** → Docs & release v0.2.0

---

## Dependencies & Notes

### External Libraries (if needed)
- **SVG timeline:** Consider D3.js or lightweight alternative
- **Tooltip:** Bootstrap Popper or vanilla JS

### Known Issues / Future Work
- **IPv6 in source_id:** Needs square brackets `[2001:db8::1]:port` (not in v0.2.0 scope)
- **Compare across captures:** Future feature (v0.3.0)
- **Configurable timeline scale:** Future enhancement

### Git Workflow
```bash
# Create branch (already done)
git checkout -b feature/gui-v02-timeline-schema

# After each phase, commit:
git add <files>
git commit -m "feat(gui): render source_id and proto fields"

# When ready for review:
git push origin feature/gui-v02-timeline-schema
# Then create PR for code review
```

---

## Success Criteria

✅ **Phase 1 (Foundation):**
- [ ] source_id renders in universe sources
- [ ] proto renders in conflict table
- [ ] No visual regressions on v0.1.2 reports

✅ **Phase 2 (Timeline):**
- [ ] Timeline UI renders without errors
- [ ] Conflicts marked on timeline correctly
- [ ] Responsive on mobile screens

✅ **Phase 3 (Schema):**
- [ ] first_seen/last_seen populated correctly
- [ ] Backward compatible (v0.1.2 consumers unaffected)
- [ ] 112/112 tests passing

✅ **Phase 4 (Testing):**
- [ ] All unit tests passing
- [ ] Golden tests updated and verified
- [ ] GUI testing manual checklist complete

✅ **Phase 5 (Release):**
- [ ] Specs updated and compiled
- [ ] README reflects v0.2.0 features
- [ ] Release published on GitHub

---

**Created:** 2026-01-19 | **Status:** Ready for Phase 1 start

const state = {
  report: null,
  lastFile: null,
  activeTab: "universes",
  sort: { key: null, dir: "asc" },
  filter: "",
  rows: [],
  selected: null,
  timelineFilter: null, // { type: "universe" | "conflict", universe?, proto?, conflictKey? }
};

const columns = {
  universes: [
    { key: "universe", label: "universe_id" },
    { key: "proto", label: "protocol" },
    { key: "source_id", label: "source_id" },
    { key: "fps", label: "fps" },
    { key: "jitter_ms", label: "jitter_ms" },
    { key: "loss_rate", label: "loss_rate" },
    { key: "burst", label: "burst_count/max_burst_len" },
  ],
  flows: [
    { key: "flow", label: "flow" },
    { key: "app_proto", label: "protocol" },
    { key: "pps", label: "pps" },
    { key: "bps", label: "bps" },
    { key: "iat_jitter_ms", label: "iat_jitter_ms" },
  ],
  conflicts: [
    { key: "universe", label: "universe_id" },
    { key: "proto", label: "protocol" },
    { key: "source_a", label: "source_a" },
    { key: "source_b", label: "source_b" },
    { key: "overlap_duration_s", label: "overlap_duration_s" },
    { key: "conflict_score", label: "conflict_score" },
  ],
  compliance: [
    { key: "protocol", label: "protocol" },
    { key: "id", label: "id" },
    { key: "severity", label: "severity" },
    { key: "count", label: "occurrences" },
    { key: "examples", label: "examples" },
  ],
};

const numericColumns = {
  universes: new Set(["fps", "jitter_ms", "loss_rate"]),
  flows: new Set(["pps", "bps", "iat_jitter_ms"]),
  conflicts: new Set(["overlap_duration_s", "conflict_score"]),
  compliance: new Set(["count"]),
};

const openBtn = document.getElementById("openBtn");
const reloadBtn = document.getElementById("reloadBtn");
const fileInput = document.getElementById("fileInput");
const dropzone = document.getElementById("dropzone");
const filterInput = document.getElementById("filterInput");
const tableHead = document.getElementById("tableHead");
const tableBody = document.getElementById("tableBody");
const detailsBody = document.getElementById("detailsBody");
const statusEl = document.getElementById("status");
const errorBanner = document.getElementById("errorBanner");
const copyJsonBtn = document.getElementById("copyJsonBtn");

const summaryVersion = document.getElementById("summaryVersion");
const summaryDuration = document.getElementById("summaryDuration");
const summaryUniverses = document.getElementById("summaryUniverses");
const summaryFlows = document.getElementById("summaryFlows");
const summaryConflicts = document.getElementById("summaryConflicts");
const summaryViolations = document.getElementById("summaryViolations");

openBtn.addEventListener("click", () => fileInput.click());
fileInput.addEventListener("change", (event) => {
  const file = event.target.files[0];
  if (file) {
    loadFile(file);
  }
});

reloadBtn.addEventListener("click", () => {
  if (state.lastFile) {
    loadFile(state.lastFile);
  }
});

copyJsonBtn.addEventListener("click", async () => {
  if (!state.selected || !state.selected.raw) {
    return;
  }
  const payload = JSON.stringify(state.selected.raw, null, 2);
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(payload);
      copyJsonBtn.textContent = "Copied";
      setTimeout(() => {
        copyJsonBtn.textContent = "Copy JSON";
      }, 1200);
      return;
    }
  } catch (err) {
    // Fall through to legacy copy.
  }
  const textarea = document.createElement("textarea");
  textarea.value = payload;
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  textarea.select();
  document.execCommand("copy");
  document.body.removeChild(textarea);
  copyJsonBtn.textContent = "Copied";
  setTimeout(() => {
    copyJsonBtn.textContent = "Copy JSON";
  }, 1200);
});

filterInput.addEventListener("input", (event) => {
  state.filter = event.target.value.trim().toLowerCase();
  renderTable();
});

Array.from(document.querySelectorAll(".tab")).forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    tab.classList.add("active");
    state.activeTab = tab.dataset.tab;
    state.sort = { key: null, dir: "asc" };
    state.selected = null;
    copyJsonBtn.disabled = true;
    detailsBody.textContent = "Select a row to view details.";
    renderTable();
  });
});

["dragenter", "dragover"].forEach((eventName) => {
  dropzone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropzone.classList.add("dragover");
  });
});

["dragleave", "drop"].forEach((eventName) => {
  dropzone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropzone.classList.remove("dragover");
  });
});

dropzone.addEventListener("drop", (event) => {
  const file = event.dataTransfer.files[0];
  if (file) {
    loadFile(file);
  }
});

function loadFile(file) {
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const data = JSON.parse(reader.result);
      if (!data || typeof data !== "object") {
        throw new Error("JSON is not an object");
      }
      state.report = data;
      state.lastFile = file;
      state.selected = null;
      reloadBtn.disabled = false;
      copyJsonBtn.disabled = true;
      setErrorBanner("");
      statusEl.textContent = `Loaded: ${file.name}`;
      updateSummary();
      renderTable();
    } catch (err) {
      setErrorBanner(`Failed to parse report.json: ${err.message}`);
      statusEl.textContent = state.report
        ? "Invalid report.json (showing last valid report)."
        : "Invalid report.json";
      if (!state.report) {
        detailsBody.textContent = String(err);
      }
    }
  };
  reader.readAsText(file);
}

function setErrorBanner(message) {
  if (!message) {
    errorBanner.hidden = true;
    errorBanner.textContent = "";
    return;
  }
  errorBanner.hidden = false;
  errorBanner.textContent = message;
}

function updateSummary() {
  const report = state.report || {};
  summaryVersion.textContent = fmtOptional(report.report_version);
  const duration = report.capture_summary?.duration_s;
  summaryDuration.textContent = fmtOptional(fmtNumber(duration, 2));

  summaryUniverses.textContent = Array.isArray(report.universes)
    ? report.universes.length
    : 0;
  summaryFlows.textContent = Array.isArray(report.flows) ? report.flows.length : 0;
  summaryConflicts.textContent = Array.isArray(report.conflicts)
    ? report.conflicts.length
    : 0;

  summaryViolations.textContent = countViolations(report.compliance || []);
}

function countViolations(compliance) {
  if (!Array.isArray(compliance)) {
    return 0;
  }
  let count = 0;
  compliance.forEach((entry) => {
    if (Array.isArray(entry.violations)) {
      entry.violations.forEach((violation) => {
        count += Number(violation.count || 0);
      });
    }
  });
  return count;
}

function renderTable() {
  const report = state.report || {};
  const tab = state.activeTab;
  const rows = buildRows(report, tab);
  state.rows = rows;

  renderHeader(tab);

  const filtered = applyFilter(rows, tab);
  const sorted = applySort(filtered);
  tableBody.innerHTML = "";

  if (!state.report) {
    statusEl.textContent = "No report loaded.";
    renderTimeline(null);
    return;
  }

  statusEl.textContent = `${sorted.length} rows`;

  if (sorted.length === 0) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = columns[tab].length;
    td.className = "no-results";
    td.textContent = "No results";
    tr.appendChild(td);
    tableBody.appendChild(tr);
    renderTimeline(report);
    return;
  }

  sorted.forEach((row) => {
    const tr = document.createElement("tr");
    
    // Add data attributes for timeline sync
    if (row.universe !== undefined && row.proto !== undefined) {
      tr.setAttribute("data-universe", row.universe);
      tr.setAttribute("data-proto", row.proto);
    }
    if (row._conflictKey !== undefined) {
      tr.setAttribute("data-conflict-key", row._conflictKey);
    }
    
    tr.addEventListener("click", () => {
      Array.from(tableBody.querySelectorAll("tr")).forEach((r) =>
        r.classList.remove("selected")
      );
      tr.classList.add("selected");
      state.selected = row;
      renderDetails(tab, row);
    });

    columns[tab].forEach((col) => {
      const td = document.createElement("td");
      const value = fmtOptional(row[col.key]);
      const text = String(value);
      const truncated = truncate(text, 140);
      td.textContent = truncated;
      if (truncated !== text) {
        td.title = text;
        td.classList.add("cell-truncate");
      }
      if (isNumericColumn(tab, col.key) && text !== "N/A") {
        td.classList.add("cell-num");
      }
      // Apply protocol color-coding for proto columns
      if (col.key === "proto" && text !== "N/A") {
        td.classList.add("cell-proto");
        const protoClass = `cell-proto-${text.toLowerCase()}`;
        td.classList.add(protoClass);
      }
      // Apply source_id styling for monospace display
      if (col.key === "source_id" && text !== "N/A") {
        td.classList.add("cell-source-id");
      }
      tr.appendChild(td);
    });

    tableBody.appendChild(tr);
  });

  // Render timeline for all reports
  renderTimeline(report);
}

function renderHeader(tab) {
  tableHead.innerHTML = "";
  const tr = document.createElement("tr");
  columns[tab].forEach((col) => {
    const th = document.createElement("th");
    const isActive = state.sort.key === col.key;
    const indicator = isActive ? (state.sort.dir === "asc" ? " ▲" : " ▼") : "";
    th.textContent = `${col.label}${indicator}`;
    th.addEventListener("click", () => {
      const dir =
        state.sort.key === col.key && state.sort.dir === "asc" ? "desc" : "asc";
      state.sort = { key: col.key, dir };
      renderTable();
    });
    tr.appendChild(th);
  });
  tableHead.appendChild(tr);
}

// Helper function for conflict identification (used in buildRows)
function createConflictKey(conflict) {
  // Create a deterministic key: universe + proto + sorted sources + first_seen
  const sources = Array.isArray(conflict.sources)
    ? conflict.sources.slice().sort().join("|")
    : "";
  return `${conflict.universe}:${conflict.proto}:${sources}:${conflict.first_seen}`;
}

function buildRows(report, tab) {
  if (!report || typeof report !== "object") {
    return [];
  }
  switch (tab) {
    case "universes":
      return (report.universes || []).map((u) => {
        // Use v0.2 source_id field if available, fall back to extracting from IP/CID/name
        const sourceId = (u.sources || [])
          .map((s) => s.source_id || s.source_ip || s.cid || s.source_name)
          .filter(Boolean)
          .join(", ");
        const row = {
          universe: u.universe,
          proto: u.proto,
          source_id: sourceId || "N/A",
          fps: fmtNumber(u.fps, 2),
          jitter_ms: fmtMs(u.jitter_ms),
          loss_rate: fmtRate(u.loss_rate),
          burst: formatBurst(u),
          raw: u,
        };
        row._details = {
          universe_id: u.universe,
          protocol: u.proto,
          source_id: sourceId || "N/A",
          fps: fmtNumber(u.fps, 2),
          jitter_ms: fmtMs(u.jitter_ms),
          loss_rate: fmtRate(u.loss_rate),
          burst_count: fmtOptional(u.burst_count),
          max_burst_len: fmtOptional(u.max_burst_len),
        };
        row._filterValues = collectFilterValues(tab, row);
        return row;
      });
    case "flows":
      return (report.flows || []).map((f) => {
        const row = {
          flow: `${f.src || ""} -> ${f.dst || ""}`.trim(),
          app_proto: f.app_proto,
          pps: fmtRate(f.pps),
          bps: fmtRate(f.bps),
          iat_jitter_ms: fmtMs(f.iat_jitter_ms),
          raw: f,
        };
        row._details = {
          flow: row.flow,
          protocol: f.app_proto,
          pps: fmtRate(f.pps),
          bps: fmtRate(f.bps),
          iat_jitter_ms: fmtMs(f.iat_jitter_ms),
          max_iat_ms: fmtMs(f.max_iat_ms),
          pps_peak_1s: fmtRate(f.pps_peak_1s),
          bps_peak_1s: fmtRate(f.bps_peak_1s),
        };
        row._filterValues = collectFilterValues(tab, row);
        return row;
      });
    case "conflicts":
      return (report.conflicts || []).map((c) => {
        const sources = Array.isArray(c.sources) ? c.sources : [];
        const conflictKey = createConflictKey(c);
        const row = {
          universe: c.universe,
          proto: c.proto || "N/A",
          source_a: sources[0] || "N/A",
          source_b: sources[1] || "N/A",
          overlap_duration_s: fmtNumber(c.overlap_duration_s, 2),
          conflict_score: fmtNumber(c.conflict_score, 2),
          raw: c,
          _conflictKey: conflictKey,
        };
        row._details = {
          universe_id: c.universe,
          protocol: c.proto || "N/A",
          source_a: sources[0] || "N/A",
          source_b: sources[1] || "N/A",
          overlap_duration_s: fmtNumber(c.overlap_duration_s, 2),
          conflict_score: fmtNumber(c.conflict_score, 2),
        };
        row._filterValues = collectFilterValues(tab, row);
        return row;
      });
    case "compliance":
      return (report.compliance || []).flatMap((entry) => {
        const protocol = entry.protocol;
        const violations = Array.isArray(entry.violations) ? entry.violations : [];
        if (violations.length === 0) {
          const row = {
            protocol,
            id: "N/A",
            severity: "N/A",
            count: 0,
            examples: "",
            raw: entry,
          };
          row._details = {
            protocol,
            id: "N/A",
            severity: "N/A",
            occurrences: 0,
            examples: [],
          };
          row._filterValues = collectFilterValues(tab, row);
          return [row];
        }
        return violations.map((v) => {
          const examples = Array.isArray(v.examples) ? v.examples : [];
          const row = {
            protocol,
            id: v.id,
            severity: v.severity,
            count: v.count,
            examples: examples.slice(0, 3).join("; "),
            raw: v,
          };
          row._details = {
            protocol,
            id: v.id,
            severity: v.severity,
            occurrences: v.count,
            examples,
          };
          row._filterValues = collectFilterValues(tab, row);
          return row;
        });
      });
    default:
      return [];
  }
}

function collectFilterValues(tab, row) {
  return columns[tab].map((col) => String(row[col.key] ?? ""));
}

function applyFilter(rows, tab) {
  if (!state.filter) {
    return rows;
  }
  return rows.filter((row) =>
    row._filterValues
      .map((value) => value.toLowerCase())
      .some((value) => value.includes(state.filter))
  );
}

function applySort(rows) {
  if (!state.sort.key) {
    return rows;
  }
  const { key, dir } = state.sort;
  return [...rows].sort((a, b) => {
    const left = a[key];
    const right = b[key];
    const result = compareValues(left, right);
    return dir === "asc" ? result : -result;
  });
}

function compareValues(left, right) {
  const leftNum = Number(left);
  const rightNum = Number(right);
  const leftIsNum = !Number.isNaN(leftNum) && left !== null && left !== "";
  const rightIsNum = !Number.isNaN(rightNum) && right !== null && right !== "";
  if (leftIsNum && rightIsNum) {
    return leftNum - rightNum;
  }
  const leftStr = String(left ?? "").toLowerCase();
  const rightStr = String(right ?? "").toLowerCase();
  if (leftStr === rightStr) {
    return 0;
  }
  return leftStr > rightStr ? 1 : -1;
}

function isNumericColumn(tab, key) {
  return numericColumns[tab] && numericColumns[tab].has(key);
}

function renderDetails(tab, row) {
  detailsBody.innerHTML = "";
  if (!row) {
    detailsBody.textContent = "Select a row to view details.";
    copyJsonBtn.disabled = true;
    return;
  }

  copyJsonBtn.disabled = false;

  if (tab === "compliance") {
    renderComplianceDetails(row);
    return;
  }

  const details = row._details || {};
  const section = document.createElement("div");
  const overviewTitle = document.createElement("div");
  overviewTitle.className = "details-section-title";
  overviewTitle.textContent = "Overview";
  section.appendChild(overviewTitle);

  const list = document.createElement("div");
  list.className = "details-list";
  Object.keys(details).forEach((key) => {
    const value = fmtOptional(details[key]);
    const keyEl = document.createElement("div");
    keyEl.className = "details-key";
    keyEl.textContent = key;
    const valEl = document.createElement("div");
    valEl.textContent = String(value);
    list.appendChild(keyEl);
    list.appendChild(valEl);
  });
  section.appendChild(list);

  const rawTitle = document.createElement("div");
  rawTitle.className = "details-section-title";
  rawTitle.textContent = "Raw JSON";
  section.appendChild(rawTitle);

  const rawBlock = document.createElement("pre");
  rawBlock.className = "details-json";
  rawBlock.textContent = JSON.stringify(row.raw, null, 2);
  section.appendChild(rawBlock);

  detailsBody.appendChild(section);
}

function renderComplianceDetails(row) {
  const details = row._details || {};
  const section = document.createElement("div");

  const overviewTitle = document.createElement("div");
  overviewTitle.className = "details-section-title";
  overviewTitle.textContent = "Violation";
  section.appendChild(overviewTitle);

  const list = document.createElement("div");
  list.className = "details-list";
  const overviewPairs = [
    ["protocol", details.protocol],
    ["id", details.id],
    ["severity", details.severity],
    ["occurrences", details.occurrences],
  ];
  overviewPairs.forEach(([key, value]) => {
    const keyEl = document.createElement("div");
    keyEl.className = "details-key";
    keyEl.textContent = key;
    const valEl = document.createElement("div");
    valEl.textContent = String(fmtOptional(value));
    list.appendChild(keyEl);
    list.appendChild(valEl);
  });
  section.appendChild(list);

  const examplesTitle = document.createElement("div");
  examplesTitle.className = "details-section-title";
  examplesTitle.textContent = "Examples";
  section.appendChild(examplesTitle);

  const examplesList = document.createElement("ul");
  examplesList.className = "details-examples";
  const examples = Array.isArray(details.examples) ? details.examples : [];
  if (examples.length === 0) {
    const item = document.createElement("li");
    item.textContent = "N/A";
    examplesList.appendChild(item);
  } else {
    examples.forEach((example) => {
      const item = document.createElement("li");
      item.textContent = String(example);
      examplesList.appendChild(item);
    });
  }
  section.appendChild(examplesList);

  const rawTitle = document.createElement("div");
  rawTitle.className = "details-section-title";
  rawTitle.textContent = "Raw JSON";
  section.appendChild(rawTitle);

  const rawBlock = document.createElement("pre");
  rawBlock.className = "details-json";
  rawBlock.textContent = JSON.stringify(row.raw, null, 2);
  section.appendChild(rawBlock);

  detailsBody.appendChild(section);
}

function truncate(text, maxLen) {
  if (text.length <= maxLen) {
    return text;
  }
  return `${text.slice(0, maxLen - 3)}...`;
}

function fmtOptional(value) {
  if (value === null || value === undefined || value === "") {
    return "N/A";
  }
  return value;
}

function fmtNumber(value, digits) {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return null;
  }
  const num = Number(value);
  if (Number.isNaN(num)) {
    return null;
  }
  return num.toFixed(digits);
}

function fmtMs(value) {
  const formatted = fmtNumber(value, 2);
  return formatted === null ? null : formatted;
}

function fmtRate(value) {
  const formatted = fmtNumber(value, 2);
  return formatted === null ? null : formatted;
}

function formatBurst(u) {
  if (u.burst_count === undefined && u.max_burst_len === undefined) {
    return null;
  }
  return `${fmtOptional(u.burst_count)}/${fmtOptional(u.max_burst_len)}`;
}
// Timeline visualization functions
function extractTimelineData(report) {
  if (!report || !report.universes) {
    return { universes: [], conflicts: [], duration: 0, startTime: 0, endTime: 0 };
  }

  // Extract universe timeline data
  const universes = (report.universes || [])
    .filter((u) => u.first_seen !== undefined && u.last_seen !== undefined)
    .map((u) => ({
      universe: u.universe,
      proto: u.proto,
      first_seen: u.first_seen,
      last_seen: u.last_seen,
    }));

  // Extract conflict timeline data
  const conflicts = (report.conflicts || [])
    .filter((c) => c.first_seen !== undefined)
    .map((c) => ({
      universe: c.universe,
      proto: c.proto || "unknown",
      first_seen: c.first_seen,
      sources: c.sources || [],
    }));

  // Calculate timeline bounds
  const allTimes = [
    ...universes.map((u) => u.first_seen),
    ...universes.map((u) => u.last_seen),
    ...conflicts.map((c) => c.first_seen),
  ];

  if (allTimes.length === 0) {
    return { universes: [], conflicts: [], duration: 0, startTime: 0, endTime: 0 };
  }

  const startTime = Math.min(...allTimes);
  const endTime = Math.max(...allTimes);
  const duration = endTime - startTime || 0.001; // Avoid division by zero

  return { universes, conflicts, duration, startTime, endTime };
}

function formatTimestamp(seconds) {
  if (seconds === undefined || seconds === null) return "N/A";
  const num = Number(seconds);
  if (Number.isNaN(num)) return "N/A";
  
  if (num < 60) {
    return `${num.toFixed(2)}s`;
  }
  const minutes = Math.floor(num / 60);
  const secs = (num % 60).toFixed(2);
  return `${minutes}m ${secs}s`;
}

function renderTimeline(report) {
  const timelineSection = document.getElementById("timelineSection");
  const timelineSvg = document.getElementById("timelineSvg");

  const data = extractTimelineData(report);

  if (data.universes.length === 0 && data.conflicts.length === 0) {
    timelineSection.hidden = true;
    return;
  }

  timelineSection.hidden = false;

  // Update timeline info
  document.getElementById("timelineStart").textContent = `Start: ${formatTimestamp(data.startTime)}`;
  document.getElementById("timelineDuration").textContent = `Duration: ${formatTimestamp(data.duration)}`;
  document.getElementById("timelineEnd").textContent = `End: ${formatTimestamp(data.endTime)}`;

  // SVG dimensions
  const padding = { top: 20, right: 20, bottom: 20, left: 100 };
  const barHeight = 20;
  const universeCount = data.universes.length + (data.conflicts.length > 0 ? 1 : 0);
  const svgHeight = Math.max(200, universeCount * (barHeight + 10) + padding.top + padding.bottom);
  const svgWidth = Math.max(600, window.innerWidth - 40);

  timelineSvg.setAttribute("viewBox", `0 0 ${svgWidth} ${svgHeight}`);
  timelineSvg.setAttribute("width", svgWidth);
  timelineSvg.setAttribute("height", svgHeight);
  timelineSvg.innerHTML = "";

  const chartWidth = svgWidth - padding.left - padding.right;
  const chartHeight = svgHeight - padding.top - padding.bottom;

  // Draw background
  const bg = document.createElementNS("http://www.w3.org/2000/svg", "rect");
  bg.setAttribute("x", padding.left);
  bg.setAttribute("y", padding.top);
  bg.setAttribute("width", chartWidth);
  bg.setAttribute("height", chartHeight);
  bg.setAttribute("fill", "#f9f9f9");
  bg.setAttribute("stroke", "#ddd");
  bg.setAttribute("stroke-width", "1");
  timelineSvg.appendChild(bg);

  // Helper to convert time to x position
  const timeToX = (time) => {
    const normalized = (time - data.startTime) / (data.duration || 1);
    return padding.left + normalized * chartWidth;
  };

  let yPos = padding.top + 10;

  // Draw universe bars
  data.universes.forEach((u) => {
    const x1 = timeToX(u.first_seen);
    const x2 = timeToX(u.last_seen);
    const barWidth = Math.max(2, x2 - x1); // Ensure minimum visibility

    // Universe label
    const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
    label.setAttribute("x", padding.left - 10);
    label.setAttribute("y", yPos + barHeight / 2);
    label.setAttribute("text-anchor", "end");
    label.setAttribute("dominant-baseline", "middle");
    label.setAttribute("font-size", "12");
    label.setAttribute("fill", "#333");
    label.textContent = `U${u.universe}`;
    timelineSvg.appendChild(label);

    // Universe bar
    const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    rect.setAttribute("x", x1);
    rect.setAttribute("y", yPos);
    rect.setAttribute("width", barWidth);
    rect.setAttribute("height", barHeight);
    rect.setAttribute("fill", u.proto === "sacn" ? "#ffeceb" : "#dbeef8");
    rect.setAttribute("stroke", u.proto === "sacn" ? "#d32f2f" : "#1565c0");
    rect.setAttribute("stroke-width", "1");
    rect.setAttribute("class", "timeline-bar");
    
    // Data attributes for sync
    rect.setAttribute("data-universe", u.universe);
    rect.setAttribute("data-proto", u.proto);
    rect.style.cursor = "pointer";
    
    // Tooltip
    const title = document.createElementNS("http://www.w3.org/2000/svg", "title");
    title.textContent = `Universe ${u.universe} (${u.proto})\n${formatTimestamp(u.first_seen)} - ${formatTimestamp(u.last_seen)}\nClick to filter`;
    rect.appendChild(title);
    
    // Click handler
    rect.addEventListener("click", () => {
      applyUniverseFilter(u.universe, u.proto);
    });
    
    // Hover sync
    rect.addEventListener("mouseenter", () => {
      document
        .querySelectorAll(`tr[data-universe="${u.universe}"][data-proto="${u.proto}"]`)
        .forEach((row) => row.classList.add("hover-highlight"));
    });
    rect.addEventListener("mouseleave", () => {
      document
        .querySelectorAll("tr.hover-highlight")
        .forEach((row) => row.classList.remove("hover-highlight"));
    });
    
    timelineSvg.appendChild(rect);

    yPos += barHeight + 10;
  });

  // Draw conflict markers
  if (data.conflicts.length > 0) {
    const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
    label.setAttribute("x", padding.left - 10);
    label.setAttribute("y", yPos + barHeight / 2);
    label.setAttribute("text-anchor", "end");
    label.setAttribute("dominant-baseline", "middle");
    label.setAttribute("font-size", "12");
    label.setAttribute("fill", "#333");
    label.setAttribute("font-weight", "bold");
    label.textContent = "Conflicts";
    timelineSvg.appendChild(label);

    data.conflicts.forEach((c, idx) => {
      const x = timeToX(c.first_seen);
      const conflictKey = createConflictKey(c);

      // Conflict marker (triangle)
      const points = [
        [x, yPos],
        [x + 8, yPos + barHeight],
        [x - 8, yPos + barHeight],
      ]
        .map((p) => p.join(","))
        .join(" ");

      const polygon = document.createElementNS("http://www.w3.org/2000/svg", "polygon");
      polygon.setAttribute("points", points);
      polygon.setAttribute("fill", "#ff6f00");
      polygon.setAttribute("stroke", "#e65100");
      polygon.setAttribute("stroke-width", "1");
      polygon.setAttribute("class", "timeline-conflict-marker");
      
      // Data attributes for sync
      polygon.setAttribute("data-conflict-key", conflictKey);
      polygon.setAttribute("data-universe", c.universe);
      polygon.style.cursor = "pointer";

      const title = document.createElementNS("http://www.w3.org/2000/svg", "title");
      const sourcesStr = c.sources ? c.sources.join(", ") : "unknown";
      title.textContent = `Universe ${c.universe} conflict\nSources: ${sourcesStr}\nTime: ${formatTimestamp(c.first_seen)}\nClick to focus`;
      polygon.appendChild(title);
      
      // Click handler
      polygon.addEventListener("click", () => {
        applyConflictFocus(conflictKey);
      });
      
      // Hover sync
      polygon.addEventListener("mouseenter", () => {
        const conflictRow = tableBody.querySelector(`tr[data-conflict-key="${conflictKey}"]`);
        if (conflictRow) {
          conflictRow.classList.add("hover-highlight");
        }
      });
      polygon.addEventListener("mouseleave", () => {
        document
          .querySelectorAll("tr.hover-highlight")
          .forEach((row) => row.classList.remove("hover-highlight"));
      });
      
      timelineSvg.appendChild(polygon);
    });

    yPos += barHeight + 10;
  }

  // Draw time axis labels
  const timeSteps = 5;
  for (let i = 0; i <= timeSteps; i++) {
    const time = data.startTime + (data.duration * i) / timeSteps;
    const x = timeToX(time);

    const tick = document.createElementNS("http://www.w3.org/2000/svg", "line");
    tick.setAttribute("x1", x);
    tick.setAttribute("y1", padding.top + chartHeight);
    tick.setAttribute("x2", x);
    tick.setAttribute("y2", padding.top + chartHeight + 5);
    tick.setAttribute("stroke", "#999");
    tick.setAttribute("stroke-width", "1");
    timelineSvg.appendChild(tick);

    const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
    label.setAttribute("x", x);
    label.setAttribute("y", padding.top + chartHeight + 15);
    label.setAttribute("text-anchor", "middle");
    label.setAttribute("font-size", "10");
    label.setAttribute("fill", "#666");
    label.textContent = formatTimestamp(time);
    timelineSvg.appendChild(label);
  }
}

// Timeline ↔ Table Sync Functions
function applyUniverseFilter(universe, proto) {
  state.timelineFilter = { type: "universe", universe, proto };
  
  // Hide non-matching rows
  const allRows = tableBody.querySelectorAll("tr");
  allRows.forEach((row) => {
    const rowUniverse = row.getAttribute("data-universe");
    const rowProto = row.getAttribute("data-proto");
    
    if (rowUniverse === String(universe) && rowProto === proto) {
      row.classList.remove("is-hidden");
    } else {
      row.classList.add("is-hidden");
    }
  });
  
  // Highlight matching rows
  highlightElements(
    tableBody.querySelectorAll(`tr[data-universe="${universe}"][data-proto="${proto}"]`)
  );
  
  updateFilterStatus();
  renderTable(); // Re-render to apply hiding
}

function applyConflictFocus(conflictKey) {
  state.timelineFilter = { type: "conflict", conflictKey };
  
  // Switch to conflicts tab if not already there
  if (state.activeTab !== "conflicts") {
    state.activeTab = "conflicts";
    renderTable();
  }
  
  // Highlight matching conflict row
  const matchingRow = tableBody.querySelector(`tr[data-conflict-key="${conflictKey}"]`);
  if (matchingRow) {
    highlightElements(matchingRow);
    // Scroll into view
    matchingRow.scrollIntoView({ behavior: "smooth", block: "center" });
  } else {
    showNotification("Conflict not found in current view");
  }
  
  updateFilterStatus();
}

function clearTimelineFilter() {
  state.timelineFilter = null;
  
  // Show all rows again
  const allRows = tableBody.querySelectorAll("tr");
  allRows.forEach((row) => row.classList.remove("is-hidden"));
  
  updateFilterStatus();
  renderTable();
}

function highlightElements(nodeOrNodeList) {
  // Remove previous highlights
  document.querySelectorAll(".row-highlight").forEach((el) => {
    el.classList.remove("row-highlight");
  });
  
  // Apply new highlights
  const nodes = NodeList.prototype.isPrototypeOf(nodeOrNodeList)
    ? nodeOrNodeList
    : [nodeOrNodeList];
  
  nodes.forEach((node) => {
    if (node) {
      node.classList.add("row-highlight");
      // Auto-remove highlight after 2 seconds
      setTimeout(() => {
        node.classList.remove("row-highlight");
      }, 2000);
    }
  });
}

function updateFilterStatus() {
  const filterStatusEl = document.getElementById("timelineFilterStatus");
  if (!filterStatusEl) return;
  
  if (!state.timelineFilter) {
    filterStatusEl.innerHTML = "";
    filterStatusEl.hidden = true;
    return;
  }
  
  let statusText = "";
  if (state.timelineFilter.type === "universe") {
    const { universe, proto } = state.timelineFilter;
    statusText = `Filtered: Universe ${universe} (${proto})`;
  } else if (state.timelineFilter.type === "conflict") {
    statusText = "Filtered: Conflict selected";
  }
  
  filterStatusEl.innerHTML = `
    ${statusText}
    <button id="clearFilterBtn" class="clear-filter-btn">Clear</button>
  `;
  filterStatusEl.hidden = false;
  
  document.getElementById("clearFilterBtn").addEventListener("click", clearTimelineFilter);
}

function showNotification(message) {
  const notif = document.createElement("div");
  notif.className = "timeline-notification";
  notif.textContent = message;
  document.body.appendChild(notif);
  
  setTimeout(() => notif.remove(), 2000);
}

// ESC key to clear filter
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && state.timelineFilter) {
    clearTimelineFilter();
  }
});

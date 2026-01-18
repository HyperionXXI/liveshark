const state = {
  report: null,
  lastFile: null,
  activeTab: "universes",
  sort: { key: null, dir: "asc" },
  filter: "",
  rows: [],
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

const openBtn = document.getElementById("openBtn");
const reloadBtn = document.getElementById("reloadBtn");
const fileInput = document.getElementById("fileInput");
const dropzone = document.getElementById("dropzone");
const filterInput = document.getElementById("filterInput");
const tableHead = document.getElementById("tableHead");
const tableBody = document.getElementById("tableBody");
const detailsBody = document.getElementById("detailsBody");
const statusEl = document.getElementById("status");

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
      reloadBtn.disabled = false;
      statusEl.textContent = `Loaded: ${file.name}`;
      updateSummary();
      renderTable();
    } catch (err) {
      state.report = null;
      statusEl.textContent = "Invalid report.json";
      detailsBody.textContent = String(err);
    }
  };
  reader.readAsText(file);
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

  const filtered = applyFilter(rows);
  const sorted = applySort(filtered);
  tableBody.innerHTML = "";

  if (!state.report) {
    statusEl.textContent = "No report loaded.";
    return;
  }

  statusEl.textContent = `${sorted.length} rows`;

  sorted.forEach((row) => {
    const tr = document.createElement("tr");
    tr.addEventListener("click", () => {
      Array.from(tableBody.querySelectorAll("tr")).forEach((r) =>
        r.classList.remove("selected")
      );
      tr.classList.add("selected");
      renderDetails(row.raw);
    });

    columns[tab].forEach((col) => {
      const td = document.createElement("td");
      td.textContent = fmtOptional(row[col.key]);
      tr.appendChild(td);
    });

    tableBody.appendChild(tr);
  });
}

function renderHeader(tab) {
  tableHead.innerHTML = "";
  const tr = document.createElement("tr");
  columns[tab].forEach((col) => {
    const th = document.createElement("th");
    th.textContent = col.label;
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

function buildRows(report, tab) {
  if (!report || typeof report !== "object") {
    return [];
  }
  switch (tab) {
    case "universes":
      return (report.universes || []).map((u) => {
        const sourceId = (u.sources || [])
          .map((s) => s.source_ip || s.cid || s.source_name)
          .filter(Boolean)
          .join(", ");
        return {
          universe: u.universe,
          proto: u.proto,
          source_id: sourceId || "N/A",
          fps: fmtNumber(u.fps, 2),
          jitter_ms: fmtMs(u.jitter_ms),
          loss_rate: fmtRate(u.loss_rate),
          burst: formatBurst(u),
          raw: u,
        };
      });
    case "flows":
      return (report.flows || []).map((f) => ({
        flow: `${f.src || ""} -> ${f.dst || ""}`.trim(),
        app_proto: f.app_proto,
        pps: fmtRate(f.pps),
        bps: fmtRate(f.bps),
        iat_jitter_ms: fmtMs(f.iat_jitter_ms),
        raw: f,
      }));
    case "conflicts":
      return (report.conflicts || []).map((c) => {
        const sources = Array.isArray(c.sources) ? c.sources : [];
        return {
          universe: c.universe,
          source_a: sources[0] || "N/A",
          source_b: sources[1] || "N/A",
          overlap_duration_s: fmtNumber(c.overlap_duration_s, 2),
          conflict_score: fmtNumber(c.conflict_score, 2),
          raw: c,
        };
      });
    case "compliance":
      return (report.compliance || []).flatMap((entry) => {
        const protocol = entry.protocol;
        const violations = Array.isArray(entry.violations) ? entry.violations : [];
        if (violations.length === 0) {
          return [
            {
              protocol,
              id: "N/A",
              severity: "N/A",
              count: 0,
              examples: "",
              raw: entry,
            },
          ];
        }
        return violations.map((v) => ({
          protocol,
          id: v.id,
          severity: v.severity,
          count: v.count,
          examples: (v.examples || []).slice(0, 3).join("; "),
          raw: v,
        }));
      });
    default:
      return [];
  }
}

function applyFilter(rows) {
  if (!state.filter) {
    return rows;
  }
  return rows.filter((row) =>
    Object.values(row)
      .map((value) => String(value).toLowerCase())
      .some((value) => value.includes(state.filter))
  );
}

function applySort(rows) {
  if (!state.sort.key) {
    return rows;
  }
  const { key, dir } = state.sort;
  return [...rows].sort((a, b) => {
    const left = a[key] ?? "";
    const right = b[key] ?? "";
    if (left === right) {
      return 0;
    }
    if (dir === "asc") {
      return left > right ? 1 : -1;
    }
    return left < right ? 1 : -1;
  });
}

function renderDetails(obj) {
  detailsBody.textContent = JSON.stringify(obj, null, 2);
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

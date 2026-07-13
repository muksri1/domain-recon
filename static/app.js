"use strict";

const $ = (id) => document.getElementById(id);
let lastReport = null;
let activeFilter = "ALL";

const STATUS_ORDER = ["FAIL", "WARN", "ERROR", "INFO", "PASS"];

document.addEventListener("DOMContentLoaded", () => {
  $("scan-form").addEventListener("submit", onScan);
  $("download-csv").addEventListener("click", onDownload);
  $("filters").addEventListener("click", (e) => {
    if (e.target.tagName !== "BUTTON") return;
    activeFilter = e.target.dataset.filter;
    [...$("filters").children].forEach((b) => b.classList.toggle("active", b === e.target));
    renderFindings();
  });

  // Query-param entry points: ?demo=1 renders an offline sample report;
  // ?domain=example.com auto-runs a scan (shareable scan links).
  const params = new URLSearchParams(location.search);
  if (params.get("demo") === "1") {
    loadDemo();
  } else if (params.get("domain")) {
    $("domain-input").value = params.get("domain");
    $("scan-form").requestSubmit();
  }
});

async function loadDemo() {
  try {
    const resp = await fetch("/api/demo");
    const data = await resp.json();
    lastReport = data;
    renderReport(data);
  } catch (err) {
    showError("Could not load demo data.");
  }
}

async function onScan(e) {
  e.preventDefault();
  const domain = $("domain-input").value.trim();
  if (!domain) return;

  showError(null);
  $("results").hidden = true;
  $("loading").hidden = false;
  $("scan-btn").disabled = true;

  try {
    const resp = await fetch(`/api/scan?domain=${encodeURIComponent(domain)}`);
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || `Request failed (${resp.status})`);
    lastReport = data;
    renderReport(data);
  } catch (err) {
    showError(err.message);
  } finally {
    $("loading").hidden = true;
    $("scan-btn").disabled = false;
  }
}

function showError(msg) {
  const el = $("error");
  el.hidden = !msg;
  el.textContent = msg || "";
}

function gradeColor(grade) {
  return { A: "var(--pass)", B: "var(--pass)", C: "var(--warn)",
           D: "var(--fail)", F: "var(--fail)" }[grade] || "var(--accent)";
}

function renderReport(r) {
  $("results").hidden = false;

  // Gauge
  const gauge = $("gauge");
  gauge.style.setProperty("--gauge-deg", `${(r.score / 100) * 360}deg`);
  gauge.style.setProperty("--gauge-color", gradeColor(r.grade));
  $("score").textContent = r.score;
  $("grade").textContent = r.grade;

  $("result-domain").textContent = r.domain;
  $("result-time").textContent =
    `Scanned ${new Date(r.scanned_at).toLocaleString()} · ${r.elapsed_seconds}s · ${r.findings.length} findings`;

  // Chips
  const chips = $("chips");
  chips.innerHTML = "";
  [["pass", "PASS"], ["warn", "WARN"], ["fail", "FAIL"], ["info", "INFO"], ["error", "ERROR"]]
    .forEach(([cls, key]) => {
      if (!r.counts[key]) return;
      const chip = document.createElement("span");
      chip.className = `chip ${cls}`;
      chip.textContent = `${r.counts[key]} ${key}`;
      chips.appendChild(chip);
    });

  renderCategories(r);
  renderFindings();
}

function renderCategories(r) {
  const wrap = $("categories");
  wrap.innerHTML = "";
  for (const [name, counts] of Object.entries(r.categories)) {
    const total = Object.values(counts).reduce((a, b) => a + b, 0);
    if (!total) continue;
    const card = document.createElement("div");
    card.className = "cat-card";
    const seg = (k, cls) =>
      counts[k] ? `<span class="s-${cls}" style="width:${(counts[k] / total) * 100}%"></span>` : "";
    card.innerHTML = `
      <h4>${escapeHtml(name)}</h4>
      <div class="cat-bar">
        ${seg("PASS", "pass")}${seg("WARN", "warn")}${seg("FAIL", "fail")}${seg("INFO", "info")}${seg("ERROR", "error")}
      </div>
      <div class="cat-counts">
        ${counts.FAIL ? `<span style="color:var(--fail)">✕ ${counts.FAIL}</span>` : ""}
        ${counts.WARN ? `<span style="color:var(--warn)">! ${counts.WARN}</span>` : ""}
        ${counts.PASS ? `<span style="color:var(--pass)">✓ ${counts.PASS}</span>` : ""}
        ${counts.INFO ? `<span style="color:var(--info)">i ${counts.INFO}</span>` : ""}
      </div>`;
    wrap.appendChild(card);
  }
}

function renderFindings() {
  if (!lastReport) return;
  const body = $("findings-body");
  body.innerHTML = "";
  const rows = lastReport.findings.filter(
    (f) => activeFilter === "ALL" || f.status === activeFilter
  );
  if (!rows.length) {
    body.innerHTML = `<tr><td colspan="5" class="muted">No findings for this filter.</td></tr>`;
    return;
  }
  for (const f of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><span class="status-badge ${f.status}">${f.status}</span></td>
      <td>${escapeHtml(f.category)}</td>
      <td>${escapeHtml(f.check)}</td>
      <td class="finding-detail">${escapeHtml(f.detail)}
        ${f.evidence ? `<code class="finding-evidence">${escapeHtml(f.evidence)}</code>` : ""}</td>
      <td class="finding-rec">${escapeHtml(f.recommendation || "—")}</td>`;
    body.appendChild(tr);
  }
}

function onDownload() {
  if (!lastReport) return;
  // Build the CSV from the report already in memory so we don't re-run the scan.
  const cols = ["domain", "scanned_at", "category", "check", "status",
                "severity", "detail", "recommendation", "evidence"];
  const esc = (v) => {
    const s = String(v ?? "");
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const lines = [cols.join(",")];
  for (const f of lastReport.findings) {
    const row = { domain: lastReport.domain, scanned_at: lastReport.scanned_at, ...f };
    lines.push(cols.map((c) => esc(row[c])).join(","));
  }
  const blob = new Blob([lines.join("\n")], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `recon_${lastReport.domain}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

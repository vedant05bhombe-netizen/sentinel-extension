// SENTINEL — Popup Script
const CIRC = 2 * Math.PI * 26; // r=26

// ── Tab switching ──
document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById("panel-" + tab.dataset.tab).classList.add("active");
    if (tab.dataset.tab === "analytics" || tab.dataset.tab === "history") loadAnalytics();
  });
});

// ── Backend status ──
async function checkBackend() {
  const settings = await getSettings();
  const base = settings.backendUrl || "http://localhost:8080";
  const pill = document.getElementById("statusPill");
  const text = document.getElementById("statusText");
  try {
    const r = await fetch(base + "/health", { signal: AbortSignal.timeout(3000) });
    if (r.ok) {
      pill.className = "status-pill online";
      text.textContent = "Online";
    } else throw new Error();
  } catch {
    pill.className = "status-pill offline";
    text.textContent = "Offline";
  }
}

// ── Settings ──
async function getSettings() {
  const { settings = {} } = await chrome.storage.local.get("settings");
  return { autoScan: true, blockDangerous: true, showBanner: true, notifications: true, backendUrl: "http://localhost:8080", ...settings };
}

async function loadSettings() {
  const s = await getSettings();
  document.getElementById("backendUrl").value = s.backendUrl;
  document.getElementById("toggle-auto").classList.toggle("on", s.autoScan);
  document.getElementById("toggle-block").classList.toggle("on", s.blockDangerous);
  document.getElementById("toggle-banner").classList.toggle("on", s.showBanner);
  document.getElementById("toggle-notif").classList.toggle("on", s.notifications);
}

document.querySelectorAll(".toggle").forEach(t => t.addEventListener("click", () => t.classList.toggle("on")));

document.getElementById("btnSave").addEventListener("click", async () => {
  await chrome.storage.local.set({ settings: {
    autoScan: document.getElementById("toggle-auto").classList.contains("on"),
    blockDangerous: document.getElementById("toggle-block").classList.contains("on"),
    showBanner: document.getElementById("toggle-banner").classList.contains("on"),
    notifications: document.getElementById("toggle-notif").classList.contains("on"),
    backendUrl: document.getElementById("backendUrl").value.trim() || "http://localhost:8080",
  }});
  const msg = document.getElementById("saveMsg");
  msg.style.display = "block";
  setTimeout(() => msg.style.display = "none", 2500);
});

// ── Scanner ──
document.getElementById("btnScanCurrent").addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.url) { document.getElementById("urlInput").value = tab.url; triggerScan(tab.url); }
});

document.getElementById("btnScan").addEventListener("click", () => {
  const url = document.getElementById("urlInput").value.trim();
  if (url) triggerScan(url);
});

document.getElementById("urlInput").addEventListener("keydown", e => {
  if (e.key === "Enter" && e.target.value.trim()) triggerScan(e.target.value.trim());
});

async function triggerScan(url) {
  const status = document.getElementById("scanStatus");
  const resultEl = document.getElementById("scanResult");
  document.getElementById("btnScan").disabled = true;
  resultEl.innerHTML = "";
  status.innerHTML = `<div class="loading"><div class="spin"></div>Scanning threat databases…</div>`;

  const result = await chrome.runtime.sendMessage({ type: "SCAN_URL", url });
  document.getElementById("btnScan").disabled = false;
  status.innerHTML = "";

  if (!result) {
    resultEl.innerHTML = `<div class="scan-result"><div class="result-body" style="color:#444;font-size:0.6rem;letter-spacing:0.1em">Backend unreachable. Check settings.</div></div>`;
    return;
  }

  const s = result.summary;
  const scanners = result.scanners || [];

  const scannersHtml = scanners.map(sc => {
    const cls = sc.safe === true ? "safe" : sc.safe === false ? "dangerous" : "unknown";
    const icon = sc.safe === true ? "✓" : sc.safe === false ? "✗" : "·";
    const iconColor = sc.safe === true ? "var(--green)" : sc.safe === false ? "var(--red)" : "#444";
    return `
      <div class="scanner-row">
        <div class="scanner-name">${sc.source}</div>
        <div class="meter-track"><div class="meter-fill meter-${cls}" style="width:${sc.safe === null ? 30 : 100}%"></div></div>
        <div class="scanner-icon" style="color:${iconColor}">${icon}</div>
      </div>`;
  }).join("");

  const threatChips = (s.threat_types || []).map(t => `<div class="threat-chip">${t}</div>`).join("");

  resultEl.innerHTML = `
    <div class="scan-result">
      <div class="result-header">
        <div class="verdict-badge verdict-${s.verdict}">${s.verdict}</div>
        <div class="risk-badge risk-${s.risk}">${s.risk} RISK</div>
      </div>
      <div class="result-body">
        <div class="result-domain">${result.domain}</div>
        <div class="scanner-rows">${scannersHtml}</div>
        ${threatChips ? `<div class="threats-row">${threatChips}</div>` : ""}
      </div>
      <div class="result-footer">
        <div class="result-stat">
          <div class="result-stat-key">Safe Engines</div>
          <div class="result-stat-val" style="color:var(--green)">${s.safe_count}</div>
        </div>
        <div class="result-stat">
          <div class="result-stat-key">Flagged</div>
          <div class="result-stat-val" style="color:${s.danger_count > 0 ? 'var(--red)' : '#555'}">${s.danger_count}</div>
        </div>
      </div>
    </div>`;

  // Animate meters
  setTimeout(() => {
    resultEl.querySelectorAll(".meter-fill").forEach(el => {
      const w = el.style.width;
      el.style.width = "0";
      setTimeout(() => el.style.width = w, 50);
    });
  }, 50);
}

// ── Analytics ──
async function loadAnalytics() {
  const analytics = await chrome.runtime.sendMessage({ type: "GET_ANALYTICS" });
  if (!analytics?.totals) { renderEmpty(); return; }

  const t = analytics.totals;
  const total = (t.safe||0) + (t.suspicious||0) + (t.dangerous||0) + (t.unknown||0);

  // Counts
  document.getElementById("totalCount").textContent = total;
  document.getElementById("safeCount").textContent = t.safe || 0;
  document.getElementById("susCount").textContent = t.suspicious || 0;
  document.getElementById("dangerCount").textContent = t.dangerous || 0;

  // Donut
  if (total > 0) {
    const safeF = (t.safe||0)/total;
    const susF  = (t.suspicious||0)/total;
    const danF  = (t.dangerous||0)/total;
    let offset = 0;
    function setSeg(id, frac) {
      const el = document.getElementById(id);
      if (!el) return;
      const len = frac * CIRC;
      el.setAttribute("stroke-dasharray", `${len} ${CIRC}`);
      el.setAttribute("stroke-dashoffset", -offset);
      offset += len;
    }
    setSeg("donut-safe", safeF);
    setSeg("donut-sus", susF);
    setSeg("donut-danger", danF);
  }

  document.getElementById("pct-safe").textContent    = total ? Math.round((t.safe||0)/total*100) + "%" : "—";
  document.getElementById("pct-sus").textContent     = total ? Math.round((t.suspicious||0)/total*100) + "%" : "—";
  document.getElementById("pct-danger").textContent  = total ? Math.round((t.dangerous||0)/total*100) + "%" : "—";
  document.getElementById("pct-unknown").textContent = total ? Math.round((t.unknown||0)/total*100) + "%" : "—";

  // Bar chart
  renderBarChart(analytics.daily || {});

  // History
  renderRecent(analytics.recentScans || []);
}

function renderBarChart(daily) {
  const chart = document.getElementById("barChart");
  if (!chart) return;
  const days = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date(); d.setDate(d.getDate() - i);
    days.push(d.toISOString().split("T")[0]);
  }
  const maxTotal = Math.max(...days.map(d => daily[d]?.total || 0), 1);
  chart.innerHTML = days.map(d => {
    const data = daily[d] || {};
    const safeH   = ((data.safe||0) / maxTotal) * 46;
    const susH    = ((data.suspicious||0) / maxTotal) * 46;
    const dangerH = ((data.dangerous||0) / maxTotal) * 46;
    const label   = d.slice(5);
    return `
      <div class="bar-col">
        <div class="bar-stack" style="height:46px">
          ${dangerH > 0 ? `<div class="bar-seg" style="height:${dangerH}px;background:var(--red)"></div>` : ""}
          ${susH > 0    ? `<div class="bar-seg" style="height:${susH}px;background:var(--yellow)"></div>` : ""}
          ${safeH > 0   ? `<div class="bar-seg" style="height:${safeH}px;background:var(--green)"></div>` : ""}
          ${(safeH+susH+dangerH) === 0 ? `<div class="bar-seg" style="height:2px;background:var(--border)"></div>` : ""}
        </div>
        <div class="bar-label">${label}</div>
      </div>`;
  }).join("");
}

function renderRecent(scans) {
  const list = document.getElementById("recentList");
  if (!list) return;
  if (!scans.length) {
    list.innerHTML = `<div class="empty-state"><span class="empty-icon">📡</span><div class="empty-text">No scans yet</div></div>`;
    return;
  }
  list.innerHTML = scans.map(s => {
    const time = new Date(s.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    return `
      <div class="recent-item">
        <span class="recent-badge badge-${s.verdict}">${s.verdict}</span>
        <span class="recent-url" title="${s.url}">${s.url}</span>
        <span class="recent-time">${time}</span>
      </div>`;
  }).join("");
}

function renderEmpty() {
  ["totalCount","safeCount","susCount","dangerCount"].forEach(id => document.getElementById(id).textContent = "0");
  const list = document.getElementById("recentList");
  if (list) list.innerHTML = `<div class="empty-state"><span class="empty-icon">📡</span><div class="empty-text">No scans recorded yet</div></div>`;
}

// ── Clear ──
document.getElementById("btnClear")?.addEventListener("click", async () => {
  if (confirm("Clear all analytics data?")) {
    await chrome.runtime.sendMessage({ type: "CLEAR_ANALYTICS" });
    loadAnalytics();
  }
});

// ── Init ──
checkBackend();
loadSettings();
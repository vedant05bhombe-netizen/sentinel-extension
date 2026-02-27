// SENTINEL - Content Script

let lastScannedUrl = null; // FIX 4: track by URL instead of boolean flag

// Show scanning overlay immediately when page starts loading
function showScanningOverlay(url) {
  if (lastScannedUrl === url) return; // FIX 4: won't break on SPA navigation
  lastScannedUrl = url;

  const overlay = document.createElement("div");
  overlay.id = "sentinel-overlay";
  overlay.innerHTML = `
    <div id="sentinel-overlay-box">
      <div id="sentinel-overlay-logo">SENTINEL</div>
      <div id="sentinel-overlay-spinner"></div>
      <div id="sentinel-overlay-title">Scanning URL for threats…</div>
      <div id="sentinel-overlay-url">${url.length > 60 ? url.slice(0, 60) + "…" : url}</div>
      <div id="sentinel-overlay-subs">Checking Google Safe Browsing · VirusTotal</div>
    </div>
  `;

  const style = document.createElement("style");
  style.id = "sentinel-overlay-style";
  style.textContent = `
    #sentinel-overlay {
      position: fixed;
      inset: 0;
      z-index: 2147483647;
      background: rgba(6,6,6,0.97);
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: 'DM Mono', 'Courier New', monospace;
      animation: sentinel-fade-in 0.2s ease;
    }
    @keyframes sentinel-fade-in { from{opacity:0} to{opacity:1} }
    @keyframes sentinel-fade-out { from{opacity:1} to{opacity:0} }

    #sentinel-overlay-box {
      text-align: center;
      padding: 3rem 2.5rem;
      border: 1px solid #2a2a2a;
      background: #0f0f0f;
      max-width: 420px;
      width: 90%;
    }
    #sentinel-overlay-logo {
      font-family: 'Bebas Neue', 'Impact', sans-serif;
      font-size: 2rem;
      letter-spacing: 0.2em;
      color: #d4a853;
      margin-bottom: 2rem;
    }
    #sentinel-overlay-spinner {
      width: 36px; height: 36px;
      border: 2px solid #2a2a2a;
      border-top-color: #d4a853;
      border-radius: 50%;
      animation: sentinel-spin 0.8s linear infinite;
      margin: 0 auto 1.5rem;
    }
    @keyframes sentinel-spin { to { transform: rotate(360deg); } }
    #sentinel-overlay-title {
      font-size: 0.8rem;
      letter-spacing: 0.15em;
      text-transform: uppercase;
      color: #f2ede7;
      margin-bottom: 0.8rem;
    }
    #sentinel-overlay-url {
      font-size: 0.62rem;
      color: #666;
      margin-bottom: 0.5rem;
      word-break: break-all;
    }
    #sentinel-overlay-subs {
      font-size: 0.55rem;
      letter-spacing: 0.12em;
      color: #444;
      text-transform: uppercase;
      animation: sentinel-blink 1.5s ease-in-out infinite;
    }
    @keyframes sentinel-blink { 0%,100%{opacity:1} 50%{opacity:0.3} }

    /* SAFE result */
    #sentinel-overlay.result-safe #sentinel-overlay-box { border-color: #27ae60; }
    #sentinel-overlay.result-safe #sentinel-overlay-title { color: #27ae60; }

    /* WARNING banner (stays on page) */
    #sentinel-warning-banner {
      position: fixed;
      top: 0; left: 0; right: 0;
      z-index: 2147483647;
      background: linear-gradient(135deg, #1a0a00, #2d1200);
      border-bottom: 2px solid #f39c12;
      font-family: 'DM Mono', 'Courier New', monospace;
      animation: sentinel-slide-down 0.3s ease;
    }
    @keyframes sentinel-slide-down { from{transform:translateY(-100%)} to{transform:translateY(0)} }
    #sentinel-banner-inner {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 12px 20px;
      gap: 16px;
      flex-wrap: wrap;
    }
    #sentinel-banner-left { display: flex; align-items: center; gap: 12px; }
    #sentinel-banner-icon { font-size: 22px; }
    #sentinel-banner-title { color: #f39c12; font-size: 13px; font-weight: bold; letter-spacing: 0.05em; }
    #sentinel-banner-sub { color: #c9a87a; font-size: 11px; margin-top: 2px; }
    #sentinel-banner-actions { display: flex; gap: 8px; }
    #sentinel-btn-back {
      background: #f39c12; color: #000; border: none;
      padding: 7px 16px; font-family: inherit; font-size: 11px;
      letter-spacing: 0.1em; text-transform: uppercase; cursor: pointer; font-weight: bold;
    }
    #sentinel-btn-back:hover { background: #fff; }
    #sentinel-btn-dismiss {
      background: transparent; color: #666; border: 1px solid #444;
      padding: 7px 16px; font-family: inherit; font-size: 11px;
      letter-spacing: 0.1em; text-transform: uppercase; cursor: pointer;
    }
    #sentinel-btn-dismiss:hover { color: #fff; border-color: #fff; }
  `;

  document.documentElement.appendChild(style);
  document.documentElement.appendChild(overlay);
}

function dismissOverlay(verdict) {
  const overlay = document.getElementById("sentinel-overlay");
  if (!overlay) return;

  if (verdict === "SAFE") {
    overlay.classList.add("result-safe");
    document.getElementById("sentinel-overlay-spinner").style.borderTopColor = "#27ae60";
    document.getElementById("sentinel-overlay-title").textContent = "✓ URL is Safe — Loading page…";
    document.getElementById("sentinel-overlay-subs").textContent = "No threats detected";
    setTimeout(() => {
      overlay.style.animation = "sentinel-fade-out 0.4s ease forwards";
      setTimeout(() => overlay.remove(), 400);
    }, 600);
  } else {
    overlay.style.animation = "sentinel-fade-out 0.3s ease forwards";
    setTimeout(() => overlay.remove(), 300);
  }
}

// Listen for messages from background
chrome.runtime.onMessage.addListener(function(msg) {
  if (msg.type === "SENTINEL_SCAN_START") {
    showScanningOverlay(msg.url);
  }
  if (msg.type === "SENTINEL_SCAN_DONE") {
    dismissOverlay(msg.verdict);
  }
  if (msg.type === "SENTINEL_WARNING") {
    dismissOverlay("SUSPICIOUS");
    injectWarningBanner(msg);
  }
});

function injectWarningBanner({ url, verdict, risk, threats }) {
  if (document.getElementById("sentinel-warning-banner")) return;

  const threats_str = (threats || []).join(", ") || "Unknown threat";

  const banner = document.createElement("div");
  banner.id = "sentinel-warning-banner";
  banner.innerHTML = `
    <div id="sentinel-banner-inner">
      <div id="sentinel-banner-left">
        <span id="sentinel-banner-icon">⚠️</span>
        <div>
          <div id="sentinel-banner-title">SENTINEL — Suspicious URL Detected</div>
          <div id="sentinel-banner-sub"></div>
        </div>
      </div>
      <div id="sentinel-banner-actions">
        <button id="sentinel-btn-back" onclick="history.back()">← Go Back</button>
        <button id="sentinel-btn-dismiss">Proceed Anyway</button>
      </div>
    </div>
  `;

  // FIX 1: use textContent to prevent XSS from threat names
  banner.querySelector("#sentinel-banner-sub").textContent = `Risk: ${risk} · Threats: ${threats_str}`;

  // FIX 2: fall back to documentElement if body doesn't exist yet
  const target = document.body || document.documentElement;
  target.prepend(banner);

  // FIX 3: wait for paint before reading offsetHeight
  requestAnimationFrame(() => {
    if (document.body) {
      document.body.style.marginTop = banner.offsetHeight + "px";
    }
  });

  document.getElementById("sentinel-btn-dismiss").addEventListener("click", () => {
    banner.remove();
    if (document.body) document.body.style.marginTop = "";
  });
}

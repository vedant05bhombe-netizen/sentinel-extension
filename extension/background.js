// SENTINEL - Background Service Worker
const BACKEND_URL = "http://localhost:8000";
const CACHE_TTL_MS = 10 * 60 * 1000;

console.log("[Sentinel] Service worker started!");

var memCache = {};

// ── Persistent Cache ──────────────────────────
async function setCache(url, result) {
  memCache[url] = { result: result, ts: Date.now() };
  try {
    const key = "cache_" + btoa(url).slice(0, 60);
    await chrome.storage.local.set({ [key]: { result: result, ts: Date.now() } });
  } catch (e) {
    console.log("[Sentinel] Cache write error:", e.message);
  }
}

async function getCache(url) {
  // Check memory first (fastest)
  if (memCache[url] && Date.now() - memCache[url].ts < CACHE_TTL_MS) {
    return memCache[url].result;
  }
  // Check persistent storage
  try {
    const key = "cache_" + btoa(url).slice(0, 60);
    const data = await chrome.storage.local.get(key);
    if (data[key] && Date.now() - data[key].ts < CACHE_TTL_MS) {
      memCache[url] = data[key]; // warm up memory cache
      return data[key].result;
    }
  } catch (e) {}
  return null;
}

// ── Main URL Check ────────────────────────────
async function checkUrl(url, tabId) {
  console.log("[Sentinel] Checking:", url);

  if (!url || !url.startsWith("http")) return null;
  if (url.includes("localhost") || url.includes("127.0.0.1")) return null;
  if (url.startsWith("chrome")) return null;

  // Persistent cache hit — instant, no API call
  const cached = await getCache(url);
  if (cached) {
    console.log("[Sentinel] Cache hit (persistent):", url);
    return cached;
  }

  // Show scanning overlay
  if (tabId) {
    chrome.tabs.sendMessage(tabId, { type: "SENTINEL_SCAN_START", url: url }).catch(() => {});
  }

  try {
    const resp = await fetch(BACKEND_URL + "/scan/extension", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    });

    if (!resp.ok) return null;

    const result = await resp.json();
    console.log("[Sentinel] Result:", result.summary.verdict, url);

    // Save to persistent cache — remembered forever
    await setCache(url, result);
    await recordScan(url, result);
    return result;
  } catch (e) {
    console.log("[Sentinel] Fetch error:", e.message);
    if (tabId) {
      chrome.tabs.sendMessage(tabId, { type: "SENTINEL_SCAN_DONE", verdict: "UNKNOWN" }).catch(() => {});
    }
    return null;
  }
}

// ── Analytics ─────────────────────────────────
async function recordScan(url, result) {
  try {
    var data = await chrome.storage.local.get("analytics");
    var analytics = data.analytics || {};
    var today = new Date().toISOString().split("T")[0];

    if (!analytics.daily) analytics.daily = {};
    if (!analytics.daily[today]) analytics.daily[today] = { safe: 0, suspicious: 0, dangerous: 0, unknown: 0, total: 0 };

    var verdict = (result.summary.verdict || "unknown").toLowerCase();
    analytics.daily[today][verdict] = (analytics.daily[today][verdict] || 0) + 1;
    analytics.daily[today].total = (analytics.daily[today].total || 0) + 1;

    if (!analytics.recentScans) analytics.recentScans = [];
    analytics.recentScans.unshift({
      url: url.length > 80 ? url.slice(0, 80) + "..." : url,
      verdict: result.summary.verdict || "UNKNOWN",
      risk: result.summary.risk || "UNKNOWN",
      ts: Date.now()
    });
    analytics.recentScans = analytics.recentScans.slice(0, 50);

    if (!analytics.totals) analytics.totals = { safe: 0, suspicious: 0, dangerous: 0, unknown: 0 };
    analytics.totals[verdict] = (analytics.totals[verdict] || 0) + 1;

    await chrome.storage.local.set({ analytics: analytics });
  } catch (e) {
    console.log("[Sentinel] Analytics error:", e.message);
  }
}

// ── Badge ─────────────────────────────────────
function updateBadge(verdict) {
  const map = {
    SAFE:       { text: "OK", color: "#27ae60" },
    SUSPICIOUS: { text: "!",  color: "#f39c12" },
    DANGEROUS:  { text: "X",  color: "#c0392b" },
    UNKNOWN:    { text: "?",  color: "#555555" },
  };
  const cfg = map[verdict] || map.UNKNOWN;
  chrome.action.setBadgeText({ text: cfg.text });
  chrome.action.setBadgeBackgroundColor({ color: cfg.color });
}

// ── Tab Listeners ─────────────────────────────
chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
  if (changeInfo.status === "loading" && tab.url && tab.url.startsWith("http")) {
    console.log("[Sentinel] Tab loading:", tab.url);
    checkUrl(tab.url, tabId).then(function(result) {
      if (!result) return;

      var verdict = result.summary.verdict;
      updateBadge(verdict);

      if (verdict === "DANGEROUS") {
        chrome.tabs.sendMessage(tabId, { type: "SENTINEL_SCAN_DONE", verdict: "DANGEROUS" }).catch(() => {});
        setTimeout(() => {
          var blocked = chrome.runtime.getURL("blocked.html") +
            "?url=" + encodeURIComponent(tab.url) +
            "&verdict=" + verdict +
            "&threats=" + encodeURIComponent(JSON.stringify(result.summary.threat_types || []));
          chrome.tabs.update(tabId, { url: blocked });
        }, 300);
        chrome.notifications.create({
          type: "basic",
          iconUrl: "icons/icon48.png",
          title: "Sentinel - Dangerous URL Blocked",
          message: "Blocked: " + tab.url.slice(0, 60)
        });

      } else if (verdict === "SUSPICIOUS") {
        chrome.tabs.sendMessage(tabId, {
          type: "SENTINEL_WARNING",
          url: tab.url,
          verdict: verdict,
          risk: result.summary.risk,
          threats: result.summary.threat_types
        }).catch(() => {});
        chrome.notifications.create({
          type: "basic",
          iconUrl: "icons/icon48.png",
          title: "Sentinel - Suspicious URL",
          message: "Caution: " + tab.url.slice(0, 60)
        });

      } else {
        chrome.tabs.sendMessage(tabId, { type: "SENTINEL_SCAN_DONE", verdict: verdict }).catch(() => {});
      }
    });
  }
});

chrome.tabs.onActivated.addListener(function(activeInfo) {
  chrome.tabs.get(activeInfo.tabId, function(tab) {
    if (tab.url && tab.url.startsWith("http")) {
      checkUrl(tab.url, null).then(function(result) {
        if (result) updateBadge(result.summary.verdict);
      });
    }
  });
});

// ── Message Handler ───────────────────────────
chrome.runtime.onMessage.addListener(function(msg, sender, sendResponse) {
  if (msg.type === "SCAN_URL") {
    checkUrl(msg.url, null).then(sendResponse);
    return true;
  }
  if (msg.type === "GET_ANALYTICS") {
    chrome.storage.local.get("analytics").then(function(data) {
      sendResponse(data.analytics || {});
    });
    return true;
  }
  if (msg.type === "CLEAR_ANALYTICS") {
    chrome.storage.local.remove("analytics").then(function() {
      sendResponse({ ok: true });
    });
    return true;
  }
});
# 🛡️ SENTINEL — URL Safety Chrome Extension

Real-time URL threat detection. Every link you click — from any app (WhatsApp, Telegram, email) — is checked against Google Safe Browsing, VirusTotal, and URLScan.io before you land on it.

---

## 📁 Project Structure

```
sentinel-extension/
├── extension/              ← Chrome Extension (load this folder)
│   ├── manifest.json
│   ├── background.js       ← Intercepts ALL navigations, calls backend
│   ├── content.js          ← Injects warning banners into suspicious pages
│   ├── popup.html          ← Extension popup (scanner + analytics)
│   ├── popup.js
│   ├── blocked.html        ← Shown when a dangerous URL is blocked
│   └── icons/              ← Extension icons
│       ├── icon16.png
│       ├── icon32.png
│       ├── icon48.png
│       └── icon128.png
│
└── backend/                ← FastAPI backend
    ├── main.py
    └── requirements.txt
```

---

## ⚙️ STEP 1 — Set Up the Backend

### Prerequisites
- Python 3.10+

### Install dependencies
```bash
cd backend
pip install -r requirements.txt
```

### Add your API keys
Open `backend/main.py` and replace the placeholder values, or set environment variables:

```bash
export GOOGLE_API_KEY="your_google_safe_browsing_key"
export VIRUSTOTAL_API_KEY="your_virustotal_api_key"
export URLSCAN_API_KEY="your_urlscan_api_key"
```

**Where to get API keys:**
| Service | URL | Free Tier |
|---|---|---|
| Google Safe Browsing | https://console.cloud.google.com → Enable "Safe Browsing API" | ✅ Free |
| VirusTotal | https://www.virustotal.com/gui/join-us | ✅ Free (4 req/min) |
| URLScan.io | https://urlscan.io/user/signup | ✅ Free |

### Start the backend
```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

The backend will be available at: **http://localhost:8000**

Test it:
```bash
curl -X POST http://localhost:8000/scan/url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://google.com"}'
```

---

## 🌐 STEP 2 — Load the Chrome Extension

1. Open Chrome and go to `chrome://extensions/`
2. Toggle **Developer mode** ON (top-right switch)
3. Click **"Load unpacked"**
4. Select the **`extension/`** folder from this project
5. The Sentinel shield icon will appear in your toolbar

---

## 🚀 STEP 3 — How It Works

### Automatic URL Interception
The extension intercepts **every navigation** before it happens — including links clicked from:
- WhatsApp Web / Telegram Web
- Emails in browser (Gmail, Outlook)
- Any app that opens links in Chrome
- Direct URL typing in the address bar

### Flow:
```
User clicks link
       ↓
background.js intercepts (webNavigation.onBeforeNavigate)
       ↓
POST http://localhost:8000/scan/url
       ↓
Backend queries: Google Safe Browsing + VirusTotal + URLScan.io
       ↓
     SAFE?  →  Allow navigation normally
  SUSPICIOUS?  →  Inject warning banner, allow with warning
   DANGEROUS?  →  Redirect to blocked.html, show notification
```

---

## 📊 Analytics Dashboard

Click the Sentinel icon in the toolbar to open the popup with 4 tabs:

| Tab | Description |
|---|---|
| **Scanner** | Manually scan any URL or current tab |
| **Analytics** | Donut chart, daily bar chart, totals breakdown |
| **History** | Last 50 scanned URLs with verdicts |
| **Settings** | Toggle features, configure backend URL |

---

## ☁️ Optional: Deploy Backend Publicly (Hackathon Polish)

### Option A — ngrok (fastest, for demos)
```bash
# Install ngrok from https://ngrok.com
ngrok http 8000
# Copy the https://xxxxx.ngrok.io URL
# Paste it in the extension's Settings tab as Backend URL
```

### Option B — Render (free permanent hosting)
1. Push your `backend/` folder to GitHub
2. Go to https://render.com → New Web Service
3. Connect your repo, set:
   - Build: `pip install -r requirements.txt`
   - Start: `uvicorn main:app --host 0.0.0.0 --port $PORT`
4. Add environment variables for your API keys
5. Update the extension's backend URL in Settings

### Option C — Railway
```bash
npm install -g @railway/cli
railway login
cd backend
railway init
railway up
```

---

## 🎛️ Settings Reference

| Setting | Default | Description |
|---|---|---|
| Auto-scan all URLs | ON | Intercept every navigation |
| Block dangerous URLs | ON | Redirect to warning page |
| Show suspicious banners | ON | Yellow banner on suspicious sites |
| Desktop notifications | ON | Notify on threat detection |
| Backend URL | localhost:8000 | Your FastAPI server address |

---

## 🔧 Troubleshooting

**Extension shows red dot (backend offline)**
→ Make sure the backend is running: `uvicorn main:app --port 8000`

**Scans always return UNKNOWN**
→ Check your API keys are valid. Test backend directly with curl.

**URLScan.io times out**
→ This scanner takes ~20s. Normal behavior — it polls for results.

**VirusTotal rate limit**
→ Free tier allows 4 requests/minute. The extension caches results for 10 minutes to reduce API calls.

**Extension not loading**
→ Make sure Developer Mode is ON in chrome://extensions/

---

## 📝 Notes for Hackathon Demo

- The 10-minute cache prevents hitting API rate limits during demos
- Green dot = backend running, Red dot = backend offline
- Badge on extension icon shows ✓/!/✗ for last checked URL
- All analytics persist between browser sessions via chrome.storage.local

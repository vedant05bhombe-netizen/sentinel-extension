from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
import asyncio
import os
from urllib.parse import urlparse
import base64
import re
from datetime import datetime

app = FastAPI(title="Sentinel URL Scanner API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ──────────────────────────────────────────────
# API KEYS — set as environment variables
# ──────────────────────────────────────────────
GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_API_KEY", "YOUR_GOOGLE_API_KEY_HERE")
VIRUSTOTAL_KEY           = os.getenv("VIRUSTOTAL_API_KEY", "YOUR_VIRUSTOTAL_KEY_HERE")
URLSCAN_KEY              = os.getenv("URLSCAN_API_KEY", "YOUR_URLSCAN_KEY_HERE")


class URLRequest(BaseModel):
    url: str


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────
def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def extract_domain(url: str) -> str:
    try:
        return urlparse(url).netloc
    except Exception:
        return url


def vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


# ──────────────────────────────────────────────
# Scanner 1 — Google Safe Browsing
# ──────────────────────────────────────────────
async def scan_google(url: str, client: httpx.AsyncClient) -> dict:
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_KEY}"
    payload = {
        "client": {"clientId": "sentinel-url-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        res = await client.post(endpoint, json=payload, timeout=8)
        data = res.json()
        matches = data.get("matches", [])
        if matches:
            threat_types = list({m.get("threatType", "UNKNOWN") for m in matches})
            return {
                "source": "Google Safe Browsing",
                "safe": False,
                "threat_types": threat_types,
                "details": f"Matched {len(matches)} threat(s): {', '.join(threat_types)}",
            }
        return {"source": "Google Safe Browsing", "safe": True, "threat_types": [], "details": "No threats found"}
    except Exception as e:
        return {"source": "Google Safe Browsing", "safe": None, "error": str(e)}


# ──────────────────────────────────────────────
# Scanner 2 — VirusTotal
# ──────────────────────────────────────────────
async def scan_virustotal(url: str, client: httpx.AsyncClient) -> dict:
    headers = {"x-apikey": VIRUSTOTAL_KEY}
    url_id  = vt_url_id(url)
    try:
        res = await client.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers, timeout=10
        )
        if res.status_code == 404:
            submit = await client.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=10,
            )
            submit_data = submit.json()
            analysis_id = submit_data.get("data", {}).get("id", "")
            if not analysis_id:
                return {"source": "VirusTotal", "safe": None, "error": "Could not submit URL"}
            await asyncio.sleep(3)
            res = await client.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers, timeout=10
            )

        data  = res.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats") or attrs.get("stats", {})
        malicious   = stats.get("malicious", 0)
        suspicious  = stats.get("suspicious", 0)
        total       = sum(stats.values()) if stats else 0

        return {
            "source":     "VirusTotal",
            "safe":       malicious == 0 and suspicious == 0,
            "malicious":  malicious,
            "suspicious": suspicious,
            "total_engines": total,
            "details": f"{malicious} malicious, {suspicious} suspicious out of {total} engines",
        }
    except Exception as e:
        return {"source": "VirusTotal", "safe": None, "error": str(e)}


# ──────────────────────────────────────────────
# Scanner 3 — URLScan.io
# ──────────────────────────────────────────────
async def scan_urlscan(url: str, client: httpx.AsyncClient) -> dict:
    headers = {"API-Key": URLSCAN_KEY, "Content-Type": "application/json"}
    try:
        submit = await client.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            json={"url": url, "visibility": "public"},
            timeout=10,
        )
        if submit.status_code not in (200, 201):
            return {"source": "URLScan.io", "safe": None, "error": f"Submission failed: {submit.status_code}"}

        result_url = submit.json().get("api")
        if not result_url:
            return {"source": "URLScan.io", "safe": None, "error": "No result URL returned"}

        for _ in range(3):
            await asyncio.sleep(6)
            poll = await client.get(result_url, timeout=10)
            if poll.status_code == 200:
                data    = poll.json()
                verdicts = data.get("verdicts", {}).get("overall", {})
                malicious = verdicts.get("malicious", False)
                score     = verdicts.get("score", 0)
                tags      = verdicts.get("tags", [])
                screenshot = data.get("task", {}).get("screenshotURL", "")
                return {
                    "source":     "URLScan.io",
                    "safe":       not malicious,
                    "score":      score,
                    "tags":       tags,
                    "screenshot": screenshot,
                    "details":    f"Score: {score}/100 · Tags: {', '.join(tags) if tags else 'none'}",
                }

        return {"source": "URLScan.io", "safe": None, "error": "Scan timed out"}
    except Exception as e:
        return {"source": "URLScan.io", "safe": None, "error": str(e)}


# ──────────────────────────────────────────────
# Scanner 4 — PhishTank (disabled — registrations closed)
# ──────────────────────────────────────────────
async def scan_phishtank(url: str, client: httpx.AsyncClient) -> dict:
    return {
        "source": "PhishTank",
        "safe": None,
        "details": "Service unavailable — registrations disabled"
    }


# ──────────────────────────────────────────────
# Aggregate verdict
# ──────────────────────────────────────────────
def aggregate_verdict(results: list) -> dict:
    danger_count  = sum(1 for r in results if r.get("safe") is False)
    unknown_count = sum(1 for r in results if r.get("safe") is None)
    safe_count    = sum(1 for r in results if r.get("safe") is True)

    if danger_count >= 2:
        verdict = "DANGEROUS"
        risk    = "HIGH"
    elif danger_count == 1:
        verdict = "SUSPICIOUS"
        risk    = "MEDIUM"
    elif unknown_count >= 3:
        verdict = "UNKNOWN"
        risk    = "UNKNOWN"
    else:
        verdict = "SAFE"
        risk    = "LOW"

    threat_types = []
    for r in results:
        threat_types.extend(r.get("threat_types", []))
        if r.get("phishing"):
            threat_types.append("PHISHING")
        if r.get("malicious", 0) > 0:
            threat_types.append("MALWARE")

    return {
        "verdict":       verdict,
        "risk":          risk,
        "danger_count":  danger_count,
        "safe_count":    safe_count,
        "unknown_count": unknown_count,
        "threat_types":  list(set(threat_types)),
    }



@app.post("/scan/url")
async def scan_url(body: URLRequest):
    url = normalize_url(body.url)
    domain = extract_domain(url)

    if not domain:
        raise HTTPException(status_code=400, detail="Invalid URL")

    async with httpx.AsyncClient() as client:
        google_res, vt_res, pt_res = await asyncio.gather(
            scan_google(url, client),
            scan_virustotal(url, client),
            scan_phishtank(url, client),
        )
        urlscan_res = await scan_urlscan(url, client)

    results  = [google_res, vt_res, pt_res, urlscan_res]
    summary  = aggregate_verdict(results)

    return {
        "url":        url,
        "domain":     domain,
        "scanned_at": datetime.utcnow().isoformat() + "Z",
        "summary":    summary,
        "scanners":   results,
    }


@app.get("/health")
async def health():
    return {"status": "ok", "service": "sentinel-url-detector", "version": "1.0.0"}

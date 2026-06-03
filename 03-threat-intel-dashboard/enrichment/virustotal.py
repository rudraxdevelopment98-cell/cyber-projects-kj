"""VirusTotal v3 enrichment.

Given an IOC and its type, query the appropriate VT endpoint and return a
detection ratio plus context. Requires a free VT API key
(``VT_API_KEY`` env var or ``api_key`` argument). Returns ``{}`` when no key is
configured so the pipeline degrades gracefully.

Note: the VT free tier is rate-limited to ~4 requests/minute; ``main.py``
throttles accordingly.
"""

import os
from urllib.parse import quote_plus

from feeds._common import http_get

BASE = "https://www.virustotal.com/api/v3"

# Map our IOC type to the VT URL path.
_ENDPOINT = {
    "ip": "ip_addresses",
    "domain": "domains",
    "hash": "files",
    # URLs use a base64 (url-safe, no padding) identifier built below.
}


def enrich(ioc, ioc_type, api_key=None):
    api_key = api_key or os.environ.get("VT_API_KEY")
    if not api_key:
        return {}

    if ioc_type == "url":
        import base64
        ident = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
        path = f"urls/{ident}"
    elif ioc_type in _ENDPOINT:
        path = f"{_ENDPOINT[ioc_type]}/{quote_plus(ioc)}"
    else:
        return {}

    resp = http_get(f"{BASE}/{path}", headers={"x-apikey": api_key})
    if resp is None:
        return {}

    attrs = resp.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) or 0
    ratio = (malicious + suspicious) / total if total else 0.0

    return {
        "vt_malicious": malicious,
        "vt_total": total,
        "vt_detection_ratio": round(ratio, 3),
        "vt_reputation": attrs.get("reputation"),
        "vt_country": attrs.get("country"),
    }

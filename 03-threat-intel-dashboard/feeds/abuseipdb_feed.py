"""AbuseIPDB blacklist feed. Requires a free AbuseIPDB API key.

Set ``ABUSEIPDB_API_KEY`` or pass ``api_key``. Returns recently reported abusive
IPs with their confidence score carried through as a tag for the scorer.
"""

import os

from ._common import http_get, make_ioc

BLACKLIST_URL = "https://api.abuseipdb.com/api/v2/blacklist"


def fetch(limit=100, api_key=None):
    api_key = api_key or os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        return []

    resp = http_get(
        BLACKLIST_URL,
        headers={"Key": api_key, "Accept": "application/json"},
        params={"confidenceMinimum": 75, "limit": limit},
    )
    if resp is None:
        return []

    iocs = []
    for item in resp.json().get("data", []):
        score = item.get("abuseConfidenceScore", 0)
        ioc = make_ioc(
            item.get("ipAddress", ""), "ip", "AbuseIPDB",
            first_seen=item.get("lastReportedAt", ""),
            tags=[item.get("countryCode", ""), f"abuse:{score}"],
        )
        # Carry the abuse score so the scorer/enrichment can use it directly.
        ioc["abuseipdb_score"] = score
        iocs.append(ioc)
        if len(iocs) >= limit:
            break
    return iocs

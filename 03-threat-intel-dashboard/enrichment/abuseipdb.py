"""AbuseIPDB enrichment for IP indicators.

Returns the abuse confidence score (0-100), ISP, country and total reports.
Requires a free key (``ABUSEIPDB_API_KEY`` env var or ``api_key`` argument).
Only meaningful for ``ioc_type == "ip"``.
"""

import os

from feeds._common import http_get

CHECK_URL = "https://api.abuseipdb.com/api/v2/check"


def enrich(ioc, ioc_type, api_key=None):
    if ioc_type != "ip":
        return {}
    api_key = api_key or os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        return {}

    resp = http_get(
        CHECK_URL,
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ioc, "maxAgeInDays": 90},
    )
    if resp is None:
        return {}

    data = resp.json().get("data", {})
    return {
        "abuseipdb_score": data.get("abuseConfidenceScore", 0),
        "abuseipdb_reports": data.get("totalReports", 0),
        "abuseipdb_country": data.get("countryCode"),
        "abuseipdb_isp": data.get("isp"),
    }

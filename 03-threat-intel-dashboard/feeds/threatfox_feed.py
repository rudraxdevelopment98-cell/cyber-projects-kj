"""ThreatFox (abuse.ch) recent IOCs with malware + MITRE context.

ThreatFox accepts an Auth-Key header for higher limits but also serves recent
IOCs without one. We POST the documented ``get_iocs`` query.
"""

from ._common import http_post, make_ioc

API = "https://threatfox-api.abuse.ch/api/v1/"

# Map ThreatFox ioc_type strings to our normalised types.
_TYPE_MAP = {
    "ip:port": "ip",
    "domain": "domain",
    "url": "url",
    "md5_hash": "hash",
    "sha256_hash": "hash",
}


def fetch(limit=100, api_key=None):
    headers = {"Auth-Key": api_key} if api_key else {}
    resp = http_post(API, json={"query": "get_iocs", "days": 1}, headers=headers)
    if resp is None:
        return []

    payload = resp.json()
    if payload.get("query_status") != "ok":
        return []

    iocs = []
    for item in payload.get("data", []):
        raw_type = item.get("ioc_type", "")
        value = item.get("ioc", "")
        # Strip the :port suffix for ip:port indicators.
        if raw_type == "ip:port" and ":" in value:
            value = value.split(":")[0]
        iocs.append(make_ioc(
            value,
            _TYPE_MAP.get(raw_type, "other"),
            "ThreatFox",
            first_seen=(item.get("first_seen", "") or "").replace(" ", "T"),
            tags=list(filter(None, [item.get("malware_printable")] + (item.get("tags") or []))),
        ))
        if len(iocs) >= limit:
            break
    return iocs

"""AlienVault OTX subscribed-pulses feed. Requires a free OTX API key.

Set the key via the ``OTX_API_KEY`` environment variable or pass ``api_key``.
Without a key this feed returns an empty list (the pipeline continues with the
other free feeds).
"""

import os

from ._common import http_get, make_ioc

PULSES_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

# OTX indicator type -> our normalised type.
_TYPE_MAP = {
    "IPv4": "ip", "IPv6": "ip",
    "domain": "domain", "hostname": "domain",
    "URL": "url", "URI": "url",
    "FileHash-MD5": "hash", "FileHash-SHA1": "hash", "FileHash-SHA256": "hash",
}


def fetch(limit=100, api_key=None):
    api_key = api_key or os.environ.get("OTX_API_KEY")
    if not api_key:
        return []

    resp = http_get(PULSES_URL, headers={"X-OTX-API-KEY": api_key},
                    params={"limit": 10})
    if resp is None:
        return []

    iocs = []
    for pulse in resp.json().get("results", []):
        pulse_name = pulse.get("name", "")
        created = pulse.get("created", "")
        for ind in pulse.get("indicators", []):
            ntype = _TYPE_MAP.get(ind.get("type"))
            if not ntype:
                continue
            iocs.append(make_ioc(
                ind.get("indicator", ""), ntype, "AlienVault OTX",
                first_seen=ind.get("created", created),
                tags=[pulse_name] + (pulse.get("tags") or []),
            ))
            if len(iocs) >= limit:
                return iocs
    return iocs

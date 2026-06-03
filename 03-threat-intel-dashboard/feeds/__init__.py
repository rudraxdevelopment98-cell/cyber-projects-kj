"""
Threat feed collectors.

Every feed module exposes ``fetch(limit=100, api_key=None)`` returning a list of
normalised IOC dicts with this shape:

    {
        "ioc":   "<indicator value>",
        "type":  "ip" | "domain" | "url" | "hash",
        "source": "<feed name>",
        "first_seen": "<ISO8601 timestamp or ''>",
        "tags":  [ ... malware family / category tags ... ]
    }

Network calls are wrapped so a single unreachable feed never aborts the whole
aggregation run — it just returns an empty list and logs a warning.
"""

from . import otx_feed, urlhaus_feed, feodo_feed, threatfox_feed, abuseipdb_feed

# Registered feeds, in collection order.
ALL_FEEDS = [
    ("AlienVault OTX", otx_feed),
    ("URLhaus", urlhaus_feed),
    ("Feodo Tracker", feodo_feed),
    ("ThreatFox", threatfox_feed),
    ("AbuseIPDB", abuseipdb_feed),
]

__all__ = ["ALL_FEEDS", "otx_feed", "urlhaus_feed", "feodo_feed",
           "threatfox_feed", "abuseipdb_feed"]

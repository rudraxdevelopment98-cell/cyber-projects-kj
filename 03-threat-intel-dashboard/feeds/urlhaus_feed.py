"""URLhaus (abuse.ch) recent malicious URLs feed. No API key required."""

from ._common import http_get, make_ioc

RECENT_URLS = "https://urlhaus.abuse.ch/downloads/csv_recent/"


def fetch(limit=100, api_key=None):
    resp = http_get(RECENT_URLS)
    if resp is None:
        return []

    iocs = []
    for line in resp.text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        # CSV columns: id,dateadded,url,url_status,last_online,threat,tags,...
        parts = _split_csv(line)
        if len(parts) < 7:
            continue
        dateadded, url, _status, _last, _threat, tags = (
            parts[1], parts[2], parts[3], parts[4], parts[5], parts[6]
        )
        iocs.append(make_ioc(
            url, "url", "URLhaus",
            first_seen=dateadded.replace(" ", "T") + "+00:00" if dateadded else "",
            tags=[t for t in tags.split(",") if t],
        ))
        if len(iocs) >= limit:
            break
    return iocs


def _split_csv(line):
    """Minimal CSV splitter handling abuse.ch's double-quoted fields."""
    import csv
    import io
    return next(csv.reader(io.StringIO(line)))

"""Feodo Tracker (abuse.ch) botnet C2 IP blocklist. No API key required."""

from ._common import http_get, make_ioc

BLOCKLIST_CSV = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"


def fetch(limit=100, api_key=None):
    resp = http_get(BLOCKLIST_CSV)
    if resp is None:
        return []

    import csv
    import io

    iocs = []
    reader = csv.reader(io.StringIO(resp.text))
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        # Columns: first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware
        if len(row) < 6:
            continue
        first_seen, ip, port, _status, _last, malware = row[:6]
        iocs.append(make_ioc(
            ip, "ip", "Feodo Tracker",
            first_seen=first_seen.replace(" ", "T") + "+00:00" if first_seen else "",
            tags=[malware, f"c2:{port}"],
        ))
        if len(iocs) >= limit:
            break
    return iocs

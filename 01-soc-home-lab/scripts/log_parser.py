#!/usr/bin/env python3
"""
log_parser.py - Windows Event Log / Sysmon triage helper for the SOC Home Lab.

Parses an exported Windows Event Log (JSON, e.g. produced by
``wevtutil qe ... /f:json`` or a Splunk export) and surfaces the events a SOC
analyst cares about: suspicious PowerShell, failed logons, new services, LSASS
access and log clears. Designed to run with **zero third-party dependencies**.

Usage:
    python log_parser.py events.json
    python log_parser.py events.json --min-failed 5 --json

Author: Kuldeep J. Jotaniya
"""

import argparse
import json
import re
import sys
from collections import defaultdict

# EventCode -> (label, MITRE technique) for the events we triage.
INTERESTING_EVENTS = {
    "4625": ("Failed Logon", "T1110 Brute Force"),
    "4688": ("Process Creation", "T1059 Command/Scripting"),
    "7045": ("New Service Installed", "T1543.003 Windows Service"),
    "1102": ("Security Log Cleared", "T1070.001 Clear Event Logs"),
    "4720": ("User Account Created", "T1136 Create Account"),
    "10":   ("Process Accessed (Sysmon)", "T1003.001 LSASS Memory"),
    "13":   ("Registry Value Set (Sysmon)", "T1547.001 Run Keys"),
}

# Indicators that a PowerShell command line is likely malicious.
SUSPICIOUS_CMDLINE = re.compile(
    r"(-enc\b|-encodedcommand|frombase64string|-nop\b|-w\s+hidden|"
    r"downloadstring|iex\b|invoke-expression|certutil.*-urlcache|bitsadmin.*/transfer)",
    re.IGNORECASE,
)


def load_events(path):
    """Load events from a JSON file.

    Accepts either a top-level list of event objects, or an object with an
    ``events`` key. Each event is a flat dict of field -> value (the shape Splunk
    and most EVTX-to-JSON exporters produce).
    """
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        return data.get("events", [])
    return data


def _get(event, *names, default=""):
    """Return the first present field from a list of candidate names."""
    for name in names:
        if name in event and event[name] not in (None, ""):
            return event[name]
    return default


def analyse(events, min_failed=5):
    """Triage a list of events into structured detections."""
    detections = []
    failed_by_ip = defaultdict(int)

    for event in events:
        code = str(_get(event, "EventCode", "EventID", "event_id"))
        cmdline = _get(event, "CommandLine", "command_line")

        # Aggregate failed logons for brute-force detection.
        if code == "4625":
            src = _get(event, "src_ip", "IpAddress", "Source_Network_Address", default="unknown")
            failed_by_ip[src] += 1

        # Flag suspicious process creations regardless of EventCode source.
        if cmdline and SUSPICIOUS_CMDLINE.search(cmdline):
            detections.append({
                "severity": "High",
                "rule": "Suspicious command line",
                "mitre": "T1059 Command/Scripting",
                "host": _get(event, "host", "Computer", default="unknown"),
                "user": _get(event, "User", "user", "SubjectUserName", default="unknown"),
                "detail": cmdline[:300],
            })

        # LSASS access via Sysmon EventCode 10.
        if code == "10" and "lsass.exe" in _get(event, "TargetImage").lower():
            detections.append({
                "severity": "Critical",
                "rule": "LSASS memory access (possible credential dump)",
                "mitre": "T1003.001 LSASS Memory",
                "host": _get(event, "host", "Computer", default="unknown"),
                "user": _get(event, "User", "SourceUser", default="unknown"),
                "detail": f"{_get(event, 'SourceImage')} -> lsass.exe "
                          f"(GrantedAccess={_get(event, 'GrantedAccess')})",
            })

        # Other interesting single events.
        if code in ("7045", "1102", "4720"):
            label, mitre = INTERESTING_EVENTS[code]
            detections.append({
                "severity": "High" if code != "4720" else "Medium",
                "rule": label,
                "mitre": mitre,
                "host": _get(event, "host", "Computer", default="unknown"),
                "user": _get(event, "User", "SubjectUserName", default="unknown"),
                "detail": _get(event, "ServiceFileName", "Target_Account_Name", "Message",
                               default=label),
            })

    # Emit brute-force detections for IPs over the threshold.
    for src, count in failed_by_ip.items():
        if count >= min_failed:
            detections.append({
                "severity": "Medium",
                "rule": f"Brute force - {count} failed logons",
                "mitre": "T1110 Brute Force",
                "host": "-",
                "user": "-",
                "detail": f"src_ip={src} failed_attempts={count}",
            })

    return detections


def main():
    parser = argparse.ArgumentParser(description="Parse Windows/Sysmon logs for SOC triage")
    parser.add_argument("logfile", help="Path to JSON event export")
    parser.add_argument("--min-failed", type=int, default=5,
                        help="Failed-logon threshold for brute-force alerting")
    parser.add_argument("--json", action="store_true", help="Emit detections as JSON")
    args = parser.parse_args()

    events = load_events(args.logfile)
    detections = analyse(events, min_failed=args.min_failed)
    # Worst severities first.
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    detections.sort(key=lambda d: order.get(d["severity"], 9))

    if args.json:
        print(json.dumps(detections, indent=2))
        return

    print(f"Parsed {len(events)} events -> {len(detections)} detection(s)\n")
    for d in detections:
        print(f"[{d['severity']:<8}] {d['rule']}")
        print(f"           MITRE: {d['mitre']}")
        print(f"           Host: {d['host']}  User: {d['user']}")
        print(f"           {d['detail']}\n")


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
alert_formatter.py - Turn raw detections into a tidy SOC triage ticket.

Takes the JSON output of ``log_parser.py`` (or any list of detection dicts) and
renders a Markdown triage report an analyst could paste straight into a ticket /
case management tool. Includes a recommended triage action per MITRE technique.

Usage:
    python log_parser.py events.json --json | python alert_formatter.py -
    python alert_formatter.py detections.json --out triage_ticket.md

Author: Kuldeep J. Jotaniya
"""

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone

# Recommended first-response action keyed by MITRE technique prefix.
TRIAGE_PLAYBOOK = {
    "T1003": "Isolate host from network, capture memory image, force-reset any "
             "credentials that may have been cached, hunt for lateral movement.",
    "T1059": "Decode any encoded/base64 payload, identify the parent process, "
             "check the binary hash against VirusTotal, escalate if confirmed.",
    "T1110": "Block the source IP at the firewall, confirm no subsequent 4624 "
             "success, notify the account owner, enforce MFA.",
    "T1543": "Validate the service against change records, hash-check the binary, "
             "isolate the host if the service is unknown/unsigned.",
    "T1547": "Review the autostart entry, remove if unauthorised, scan for "
             "additional persistence mechanisms.",
    "T1070": "Treat as high-confidence IoC. Pivot to forwarded logs / EDR which "
             "survive local log clears; begin formal incident response.",
    "T1136": "Confirm a change ticket authorises the new account; if not, disable "
             "it and review what actions it performed.",
    "T1105": "Inspect the transferred artefact, sandbox it, block the source URL.",
}

SEVERITY_EMOJI = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵"}


def load_detections(path):
    raw = sys.stdin.read() if path == "-" else open(path, encoding="utf-8").read()
    return json.loads(raw)


def playbook_action(mitre):
    """Find the playbook action whose technique prefix matches the detection."""
    for prefix, action in TRIAGE_PLAYBOOK.items():
        if mitre.startswith(prefix):
            return action
    return "Investigate event context and escalate to a senior analyst if unclear."


def render(detections):
    sev_counts = Counter(d["severity"] for d in detections)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "# SOC Triage Ticket - Automated Detection Summary",
        "",
        f"**Generated:** {now}  ",
        f"**Total detections:** {len(detections)}  ",
        "**Severity breakdown:** "
        + ", ".join(f"{s} {sev_counts.get(s,0)}" for s in
                    ("Critical", "High", "Medium", "Low")),
        "",
        "---",
        "",
    ]

    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    for i, d in enumerate(sorted(detections, key=lambda x: order.get(x["severity"], 9)), 1):
        emoji = SEVERITY_EMOJI.get(d["severity"], "")
        lines += [
            f"## {i}. {emoji} [{d['severity']}] {d['rule']}",
            "",
            f"- **MITRE ATT&CK:** {d['mitre']}",
            f"- **Host:** `{d.get('host','-')}`",
            f"- **User:** `{d.get('user','-')}`",
            f"- **Evidence:** `{d.get('detail','')}`",
            f"- **Recommended action:** {playbook_action(d['mitre'])}",
            "",
        ]

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Format detections into a triage ticket")
    parser.add_argument("detections", help="Path to detections JSON, or '-' for stdin")
    parser.add_argument("--out", help="Write Markdown to this file instead of stdout")
    args = parser.parse_args()

    detections = load_detections(args.detections)
    markdown = render(detections)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(markdown)
        print(f"Wrote triage ticket to {args.out}", file=sys.stderr)
    else:
        print(markdown)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
Threat Intelligence Platform - aggregation, enrichment, scoring pipeline.

Pipeline stages:
  1. Collect  - pull IOCs from the registered open-source feeds.
  2. Dedupe   - merge duplicate indicators across feeds.
  3. Enrich   - query VirusTotal / AbuseIPDB for context (if API keys present).
  4. Score    - assign each IOC a 1-10 risk score (see scoring/scorer.py).
  5. Store    - write the enriched, scored dataset to data/iocs.json.

Usage:
    # Live run (uses any *_API_KEY env vars that are set):
    python main.py --collect --limit 50

    # Offline demo using the bundled enriched sample dataset:
    python main.py --demo

    # Look up a single indicator on demand:
    python main.py --lookup 45.155.205.233

Author: Kuldeep J. Jotaniya
"""

import argparse
import json
import sys
import time
from pathlib import Path

from scoring import score_ioc, classify

DATA_DIR = Path(__file__).parent / "data"
DEMO_FILE = DATA_DIR / "demo_iocs.json"
OUTPUT_FILE = DATA_DIR / "iocs.json"


# --------------------------------------------------------------------------- #
# Collection + dedup
# --------------------------------------------------------------------------- #
def collect(limit_per_feed=50):
    """Pull IOCs from every registered feed and merge duplicates."""
    from feeds import ALL_FEEDS

    merged = {}
    for name, module in ALL_FEEDS:
        try:
            items = module.fetch(limit=limit_per_feed)
        except Exception as exc:  # noqa: BLE001
            print(f"[collect] {name} failed: {exc}", file=sys.stderr)
            items = []
        print(f"[collect] {name}: {len(items)} IOC(s)", file=sys.stderr)
        for item in items:
            key = (item["ioc"], item["type"])
            if key in merged:
                # Same indicator from multiple feeds -> combine source + tags.
                existing = merged[key]
                existing["source"] = ", ".join(
                    sorted(set(existing["source"].split(", ")) | {item["source"]}))
                existing["tags"] = sorted(set(existing["tags"]) | set(item["tags"]))
                existing.update({k: v for k, v in item.items()
                                 if k == "abuseipdb_score" and v})
            else:
                merged[key] = dict(item)
    return list(merged.values())


# --------------------------------------------------------------------------- #
# Enrichment
# --------------------------------------------------------------------------- #
def enrich_all(iocs, throttle=15.0):
    """Enrich each IOC via VirusTotal + AbuseIPDB (no-op without API keys)."""
    from enrichment import virustotal, abuseipdb

    for i, ioc in enumerate(iocs, 1):
        vt = virustotal.enrich(ioc["ioc"], ioc["type"])
        ab = abuseipdb.enrich(ioc["ioc"], ioc["type"])
        ioc.update(vt)
        ioc.update(ab)
        # VT free tier is ~4 req/min; throttle only when we actually called it.
        if vt and i < len(iocs):
            time.sleep(throttle)
    return iocs


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #
def score_all(iocs):
    for ioc in iocs:
        ioc["risk_score"] = score_ioc(ioc)
        ioc["severity"] = classify(ioc["risk_score"])
    iocs.sort(key=lambda x: x["risk_score"], reverse=True)
    return iocs


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #
def save(iocs, path=OUTPUT_FILE):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    doc = {
        "generated_at": _now(),
        "total_iocs": len(iocs),
        "iocs": iocs,
    }
    Path(path).write_text(json.dumps(doc, indent=2))
    return path


def _now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# On-demand lookup
# --------------------------------------------------------------------------- #
def lookup(indicator):
    """Enrich and score a single indicator in real time."""
    from enrichment import virustotal, abuseipdb

    ioc_type = _guess_type(indicator)
    record = {"ioc": indicator, "type": ioc_type, "source": "manual-lookup",
              "first_seen": _now(), "tags": []}
    record.update(virustotal.enrich(indicator, ioc_type))
    record.update(abuseipdb.enrich(indicator, ioc_type))
    record["risk_score"] = score_ioc(record)
    record["severity"] = classify(record["risk_score"])
    return record


def _guess_type(value):
    import re
    if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", value):
        return "hash"
    if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", value):
        return "ip"
    if value.startswith("http://") or value.startswith("https://"):
        return "url"
    return "domain"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main():
    parser = argparse.ArgumentParser(description="Threat Intelligence pipeline")
    parser.add_argument("--collect", action="store_true", help="Run live feed collection")
    parser.add_argument("--demo", action="store_true", help="Use bundled demo dataset")
    parser.add_argument("--lookup", metavar="IOC", help="Enrich+score a single indicator")
    parser.add_argument("--limit", type=int, default=50, help="Max IOCs per feed")
    parser.add_argument("--no-enrich", action="store_true", help="Skip enrichment APIs")
    args = parser.parse_args()

    if args.lookup:
        print(json.dumps(lookup(args.lookup), indent=2))
        return 0

    if args.demo:
        print("[*] DEMO mode: loading bundled enriched dataset.", file=sys.stderr)
        iocs = json.loads(DEMO_FILE.read_text())["iocs"]
        iocs = score_all(iocs)
    elif args.collect:
        iocs = collect(limit_per_feed=args.limit)
        if not args.no_enrich:
            iocs = enrich_all(iocs)
        iocs = score_all(iocs)
    else:
        parser.error("specify --collect, --demo, or --lookup")

    path = save(iocs)

    # Console summary.
    from collections import Counter
    sev = Counter(i["severity"] for i in iocs)
    print(f"\n=== Threat Intel Summary ===")
    print(f"Total IOCs: {len(iocs)}")
    for s in ("Critical", "High", "Medium", "Low"):
        if sev.get(s):
            print(f"  {s:<9} {sev[s]}")
    print(f"Saved to: {path}")
    print("Top 5 by risk:")
    for ioc in iocs[:5]:
        print(f"  [{ioc['risk_score']:>2}] {ioc['severity']:<8} {ioc['type']:<6} "
              f"{ioc['ioc']}  ({ioc['source']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

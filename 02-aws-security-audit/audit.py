#!/usr/bin/env python3
"""
AWS Security Misconfiguration Audit Tool
========================================

Scans an AWS account for common security misconfigurations across IAM, S3,
EC2 and CloudTrail, maps every finding to CIS AWS Benchmark and NIST CSF
controls, and produces a machine-readable JSON file plus an executive HTML
report.

Usage
-----
  # Audit the account configured in your AWS credentials/profile:
  python audit.py --profile my-lab --region eu-west-2

  # Run against sample data with NO AWS account required (portfolio demo):
  python audit.py --demo

Author: Kuldeep J. Jotaniya
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from report import render_html, summarise


def run_live_audit(profile, region):
    """Run every registered check against a real AWS account."""
    import boto3
    from checks import get_all_check_modules

    session = boto3.Session(profile_name=profile, region_name=region)
    # Fail fast with a clear message if credentials are missing/expired.
    account = session.client("sts").get_caller_identity()["Account"]

    findings = []
    for module in get_all_check_modules():
        name = module.__name__.split(".")[-1]
        try:
            module_findings = module.run(session)
            findings.extend(module_findings)
            print(f"  [+] {name}: {len(module_findings)} finding(s)", file=sys.stderr)
        except Exception as exc:  # one failing service shouldn't abort the audit
            print(f"  [!] {name} failed: {exc}", file=sys.stderr)
    return account, findings


def load_demo_findings():
    """Load the bundled sample findings (intentionally misconfigured lab)."""
    demo_path = Path(__file__).parent / "findings" / "sample_findings.json"
    data = json.loads(demo_path.read_text())
    return data["account_id"], data["findings"]


def main():
    parser = argparse.ArgumentParser(description="AWS Security Misconfiguration Audit Tool")
    parser.add_argument("--profile", default=None, help="AWS named profile to use")
    parser.add_argument("--region", default="eu-west-2", help="AWS region (default: eu-west-2)")
    parser.add_argument("--demo", action="store_true",
                        help="Run against bundled sample data (no AWS account needed)")
    parser.add_argument("--out-dir", default=".", help="Output directory for report/findings")
    args = parser.parse_args()

    if args.demo:
        print("[*] Running in DEMO mode using bundled sample findings.", file=sys.stderr)
        account, findings = load_demo_findings()
    else:
        print(f"[*] Auditing AWS account (profile={args.profile}, region={args.region})...",
              file=sys.stderr)
        account, findings = run_live_audit(args.profile, args.region)

    summary = summarise(findings)
    out_dir = Path(args.out_dir)
    (out_dir / "findings").mkdir(parents=True, exist_ok=True)
    (out_dir / "reports").mkdir(parents=True, exist_ok=True)

    # 1. Machine-readable JSON output.
    findings_doc = {
        "account_id": account,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "findings": findings,
    }
    json_path = out_dir / "findings" / "audit_findings.json"
    json_path.write_text(json.dumps(findings_doc, indent=2))

    # 2. Executive HTML report.
    html_path = out_dir / "reports" / "audit_report.html"
    html_path.write_text(render_html(findings, account=account))

    # 3. Console summary.
    print("\n=== AWS Security Audit Summary ===")
    print(f"Account:      {account}")
    print(f"Risk score:   {summary['risk_score']}/100")
    print(f"Posture:      {summary['posture']}")
    print(f"Findings:     {summary['total_findings']}")
    for sev, n in summary["severity_breakdown"].items():
        if n:
            print(f"  {sev:<9} {n}")
    print(f"\nJSON:   {json_path}")
    print(f"Report: {html_path}")

    # Non-zero exit if Critical/High findings exist (useful in CI pipelines).
    if summary["severity_breakdown"]["Critical"] or summary["severity_breakdown"]["High"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

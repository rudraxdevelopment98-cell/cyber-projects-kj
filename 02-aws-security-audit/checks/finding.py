"""Shared helpers for building audit findings.

A *finding* is a single result produced by a check. We model it as a plain
dictionary (rather than a class) so it serialises cleanly to JSON for the
machine-readable output and feeds straight into the Jinja2 report template.
"""

from datetime import datetime, timezone

# Severity ordering is used to sort findings and to compute the risk score.
SEVERITY_WEIGHTS = {
    "Critical": 40,
    "High": 20,
    "Medium": 10,
    "Low": 3,
    "Info": 0,
}


def make_finding(check_id, name, severity, framework, resource, description,
                 remediation, status="FAIL"):
    """Build a normalised finding dictionary.

    Args:
        check_id:    Stable identifier, e.g. "IAM-001".
        name:        Human-readable title of the check.
        severity:    One of SEVERITY_WEIGHTS keys.
        framework:   Framework mapping string (CIS / NIST control IDs).
        resource:    The affected resource (ARN, bucket name, SG id, ...).
        description: What was found and why it matters.
        remediation: Step-by-step fix guidance.
        status:      "FAIL" (misconfiguration present) or "PASS".
    """
    if severity not in SEVERITY_WEIGHTS:
        raise ValueError(f"Unknown severity: {severity!r}")

    return {
        "check_id": check_id,
        "name": name,
        "severity": severity,
        "framework_mapping": framework,
        "resource": resource,
        "description": description,
        "remediation": remediation,
        "status": status,
        "detected_at": datetime.now(timezone.utc).isoformat(),
    }

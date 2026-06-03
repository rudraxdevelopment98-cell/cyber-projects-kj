"""
Risk scoring engine.

Assigns a 1-10 risk score to each enriched IOC using a weighted formula that
mirrors how a SOC analyst prioritises indicators:

    score = (vt_ratio        * 0.5)
          + (abuseipdb/100   * 0.3)
          + (recency_weight  * 0.2)

  * vt_ratio       - VirusTotal malicious/total detection ratio (0..1)
  * abuseipdb      - AbuseIPDB abuse confidence score (0..100)
  * recency_weight - 1.0 for an IOC seen today, decaying to 0 at 30 days old

The weighted result (0..1) is scaled to a 1-10 integer. Indicators with no
enrichment data still receive a floor score of 1 so nothing silently drops out
of analyst view.

This module is pure-Python and dependency-free so it is trivially unit-testable.
"""

from datetime import datetime, timezone

# Weights must sum to 1.0.
W_VT = 0.5
W_ABUSE = 0.3
W_RECENCY = 0.2

RECENCY_HORIZON_DAYS = 30


def _recency_weight(first_seen, now=None):
    """Linear decay from 1.0 (today) to 0.0 at RECENCY_HORIZON_DAYS old."""
    if not first_seen:
        return 0.0
    now = now or datetime.now(timezone.utc)
    try:
        seen = datetime.fromisoformat(str(first_seen).replace("Z", "+00:00"))
        if seen.tzinfo is None:
            seen = seen.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return 0.0
    age_days = (now - seen).total_seconds() / 86400.0
    if age_days <= 0:
        return 1.0
    if age_days >= RECENCY_HORIZON_DAYS:
        return 0.0
    return 1.0 - (age_days / RECENCY_HORIZON_DAYS)


def score_ioc(record, now=None):
    """Return an integer 1-10 risk score for an enriched IOC record.

    Expected (all optional) keys on ``record``:
        vt_detection_ratio : float 0..1
        abuseipdb_score    : int 0..100
        first_seen         : ISO8601 timestamp string
    """
    vt = float(record.get("vt_detection_ratio") or 0.0)
    abuse = float(record.get("abuseipdb_score") or 0.0)
    recency = _recency_weight(record.get("first_seen"), now=now)

    weighted = (vt * W_VT) + ((abuse / 100.0) * W_ABUSE) + (recency * W_RECENCY)

    # Scale 0..1 -> 1..10, never below the floor of 1.
    score = round(weighted * 9) + 1
    return max(1, min(10, score))


def classify(score):
    """Map a 1-10 score to a severity label used across the dashboard/report."""
    if score >= 8:
        return "Critical"
    if score >= 6:
        return "High"
    if score >= 4:
        return "Medium"
    return "Low"

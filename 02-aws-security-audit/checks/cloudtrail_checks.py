"""CloudTrail-focused audit checks: trail coverage, log validation, encryption."""

from botocore.exceptions import ClientError

from .finding import make_finding


def run(session):
    ct = session.client("cloudtrail")
    findings = []

    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
    except ClientError:
        trails = []

    # --- CT-001: No multi-region trail logging is active (CIS 3.1 / NIST AU-12) ---
    multi_region_active = False
    for trail in trails:
        name = trail.get("TrailARN", trail.get("Name"))
        try:
            status = ct.get_trail_status(Name=name)
        except ClientError:
            continue
        if trail.get("IsMultiRegionTrail") and status.get("IsLogging"):
            multi_region_active = True

    if not multi_region_active:
        findings.append(make_finding(
            "CT-001",
            "CloudTrail Not Enabled in All Regions",
            "High",
            "CIS AWS 3.1 / NIST AU-12",
            "cloudtrail/account",
            "No multi-region CloudTrail trail is actively logging. Without "
            "account-wide, all-region trails, API activity in unmonitored "
            "regions (a common attacker tactic) goes unrecorded.",
            "Create a multi-region trail that logs management events for all "
            "regions and confirm it is in the 'Logging' state.",
        ))

    # Per-trail hygiene checks.
    for trail in trails:
        name = trail.get("Name")
        arn = trail.get("TrailARN", name)

        # --- CT-002: Log file validation disabled (CIS 3.2 / NIST AU-9) ---
        if not trail.get("LogFileValidationEnabled"):
            findings.append(make_finding(
                "CT-002",
                "CloudTrail Log File Validation Disabled",
                "Medium",
                "CIS AWS 3.2 / NIST AU-9",
                arn,
                f"Trail '{name}' does not have log file integrity validation "
                "enabled, so tampering with or deletion of log files would go "
                "undetected.",
                "Enable log file validation on the trail so CloudTrail "
                "produces signed digest files for integrity verification.",
            ))

        # --- CT-003: Logs not encrypted with KMS (CIS 3.7 / NIST SC-28) ---
        if not trail.get("KmsKeyId"):
            findings.append(make_finding(
                "CT-003",
                "CloudTrail Logs Not Encrypted with KMS CMK",
                "Low",
                "CIS AWS 3.7 / NIST SC-28",
                arn,
                f"Trail '{name}' logs are not encrypted with a customer-managed "
                "KMS key, reducing control over who can decrypt audit logs.",
                "Configure the trail to encrypt log files with a KMS CMK and "
                "restrict key usage via the key policy.",
            ))

    return findings

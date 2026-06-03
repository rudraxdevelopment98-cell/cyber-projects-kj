"""S3-focused audit checks: public access, logging, encryption, versioning."""

from botocore.exceptions import ClientError

from .finding import make_finding

# Canonical group URIs that indicate public exposure via an ACL grant.
_PUBLIC_ACL_URIS = (
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
)


def run(session):
    s3 = session.client("s3")
    findings = []

    buckets = s3.list_buckets().get("Buckets", [])
    for bucket in buckets:
        name = bucket["Name"]

        # --- S3-001: Bucket publicly accessible (CIS 2.1.5 / NIST SC-7) ---
        if _is_public(s3, name):
            findings.append(make_finding(
                "S3-001",
                "S3 Bucket Publicly Accessible",
                "Critical",
                "CIS AWS 2.1.5 / NIST SC-7",
                f"s3://{name}",
                f"Bucket '{name}' is publicly accessible (public ACL grant or "
                "missing/disabled Public Access Block). Public buckets are a "
                "leading cause of cloud data breaches.",
                "Enable S3 Block Public Access at the bucket and account level, "
                "remove AllUsers/AuthenticatedUsers ACL grants, and serve "
                "public content via CloudFront with OAC instead.",
            ))

        # --- S3-002: Server access logging not enabled (CIS 2.1.2 / NIST AU-2) ---
        try:
            logging_cfg = s3.get_bucket_logging(Bucket=name)
            if "LoggingEnabled" not in logging_cfg:
                findings.append(make_finding(
                    "S3-002",
                    "S3 Bucket Logging Not Enabled",
                    "Medium",
                    "CIS AWS 2.1.2 / NIST AU-2",
                    f"s3://{name}",
                    f"Bucket '{name}' does not have server access logging "
                    "enabled, reducing forensic visibility into who accessed "
                    "objects during an incident.",
                    "Enable server access logging (or CloudTrail data events) "
                    "and ship logs to a dedicated, access-restricted log bucket.",
                ))
        except ClientError:
            pass  # Region/permission edge cases are skipped, not fatal.

        # --- S3-003: Default encryption not enforced (CIS 2.1.1 / NIST SC-28) ---
        try:
            s3.get_bucket_encryption(Bucket=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                findings.append(make_finding(
                    "S3-003",
                    "S3 Default Encryption Not Enabled",
                    "Medium",
                    "CIS AWS 2.1.1 / NIST SC-28",
                    f"s3://{name}",
                    f"Bucket '{name}' has no default server-side encryption "
                    "configured, so objects may be stored unencrypted at rest.",
                    "Enable default encryption (SSE-S3 or SSE-KMS) on the "
                    "bucket and deny unencrypted PutObject via bucket policy.",
                ))

        # --- S3-004: Versioning disabled (CIS 2.1.4 / NIST CP-9) ---
        try:
            versioning = s3.get_bucket_versioning(Bucket=name)
            if versioning.get("Status") != "Enabled":
                findings.append(make_finding(
                    "S3-004",
                    "S3 Bucket Versioning Disabled",
                    "Low",
                    "CIS AWS 2.1.4 / NIST CP-9",
                    f"s3://{name}",
                    f"Bucket '{name}' does not have versioning enabled, so "
                    "objects overwritten or deleted (e.g. by ransomware) "
                    "cannot be recovered.",
                    "Enable versioning and consider MFA Delete plus lifecycle "
                    "rules to manage non-current version storage costs.",
                ))
        except ClientError:
            pass

    return findings


def _is_public(s3, name):
    """Best-effort determination of whether a bucket is publicly exposed."""
    # 1. Public Access Block fully on => not public regardless of ACL/policy.
    try:
        pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
        if all(pab.get(k) for k in (
            "BlockPublicAcls", "IgnorePublicAcls",
            "BlockPublicPolicy", "RestrictPublicBuckets",
        )):
            return False
    except ClientError:
        # No PAB configured at all is itself a risk; fall through to ACL check.
        pass

    # 2. Inspect ACL grants for the public group URIs.
    try:
        acl = s3.get_bucket_acl(Bucket=name)
        for grant in acl.get("Grants", []):
            uri = grant.get("Grantee", {}).get("URI", "")
            if uri in _PUBLIC_ACL_URIS:
                return True
    except ClientError:
        pass

    return False

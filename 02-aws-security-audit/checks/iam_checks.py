"""IAM-focused audit checks.

Covers root account hygiene, MFA, over-privileged users, unused credentials
and password policy strength. All checks are read-only (they only call AWS
``get``/``list``/``generate`` APIs).
"""

import csv
import io
import time

from botocore.exceptions import ClientError

from .finding import make_finding


def _credential_report(iam):
    """Fetch the IAM credential report, generating it if necessary.

    AWS produces this report asynchronously, so we poll until it is ready.
    Returns a list of dict rows (one per IAM user + the root account).
    """
    for _ in range(10):
        try:
            report = iam.get_credential_report()
            content = report["Content"].decode("utf-8")
            return list(csv.DictReader(io.StringIO(content)))
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ReportNotPresent", "ReportInProgress", "ReportExpired"):
                iam.generate_credential_report()
                time.sleep(2)
                continue
            raise
    return []


def run(session):
    iam = session.client("iam")
    findings = []

    # --- IAM-001: Root account MFA not enabled (CIS 1.5 / NIST AC-2) ---
    summary = iam.get_account_summary()["SummaryMap"]
    if summary.get("AccountMFAEnabled", 0) != 1:
        findings.append(make_finding(
            "IAM-001",
            "Root Account MFA Not Enabled",
            "Critical",
            "CIS AWS 1.5 / NIST AC-2",
            "arn:aws:iam::root",
            "The AWS root account does not have multi-factor authentication "
            "enabled. The root account has unrestricted access to every "
            "resource in the account, so a compromised root password alone "
            "would grant an attacker full control.",
            "Sign in as root, open the IAM console security credentials page "
            "and enable a hardware or virtual MFA device. Store recovery "
            "codes securely and avoid using the root account for daily tasks.",
        ))

    # --- IAM-002: IAM users with full admin privileges (CIS 1.16 / NIST AC-6) ---
    for user in iam.list_users().get("Users", []):
        username = user["UserName"]
        admin = False

        # Directly attached managed policies.
        attached = iam.list_attached_user_policies(UserName=username)
        for policy in attached.get("AttachedPolicies", []):
            if policy["PolicyArn"].endswith(":policy/AdministratorAccess"):
                admin = True

        # Admin granted via group membership.
        for group in iam.list_groups_for_user(UserName=username).get("Groups", []):
            grp_attached = iam.list_attached_group_policies(GroupName=group["GroupName"])
            for policy in grp_attached.get("AttachedPolicies", []):
                if policy["PolicyArn"].endswith(":policy/AdministratorAccess"):
                    admin = True

        if admin:
            findings.append(make_finding(
                "IAM-002",
                "IAM User with Administrator Privileges",
                "High",
                "CIS AWS 1.16 / NIST AC-6",
                user["Arn"],
                f"IAM user '{username}' has the AdministratorAccess policy "
                "attached (directly or via a group). This violates least "
                "privilege: day-to-day identities should only hold the "
                "permissions they actually need.",
                "Replace AdministratorAccess with scoped policies granting "
                "only required actions. Reserve admin rights for break-glass "
                "roles assumed via STS with MFA.",
            ))

    # --- IAM-003: Access keys not rotated in 90 days (CIS 1.14 / NIST IA-5) ---
    # --- IAM-004: Console users without MFA (CIS 1.10 / NIST IA-2) ---
    for row in _credential_report(iam):
        user = row.get("user", "")
        if user == "<root_account>":
            continue

        # Stale access keys.
        for key_idx in ("1", "2"):
            active = row.get(f"access_key_{key_idx}_active") == "true"
            last_rotated = row.get(f"access_key_{key_idx}_last_rotated", "N/A")
            if active and _older_than_days(last_rotated, 90):
                findings.append(make_finding(
                    "IAM-003",
                    "Access Key Not Rotated in 90 Days",
                    "Medium",
                    "CIS AWS 1.14 / NIST IA-5",
                    f"iam-user/{user}#key{key_idx}",
                    f"Access key {key_idx} for user '{user}' was last rotated "
                    f"on {last_rotated}, more than 90 days ago. Long-lived "
                    "static keys increase the blast radius if leaked.",
                    "Rotate the access key (create new, update consumers, "
                    "delete old) and adopt short-lived STS credentials or IAM "
                    "Roles Anywhere where possible.",
                ))

        # Console-enabled user without MFA.
        if row.get("password_enabled") == "true" and row.get("mfa_active") == "false":
            findings.append(make_finding(
                "IAM-004",
                "Console User Without MFA",
                "High",
                "CIS AWS 1.10 / NIST IA-2",
                f"iam-user/{user}",
                f"IAM user '{user}' has console access (a login password) but "
                "no MFA device. Password-only console access is vulnerable to "
                "credential stuffing and phishing.",
                "Enforce MFA for all console users via an IAM policy condition "
                "(aws:MultiFactorAuthPresent) and register an MFA device.",
            ))

    # --- IAM-005: Weak account password policy (CIS 1.8 / NIST IA-5) ---
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        weaknesses = []
        if policy.get("MinimumPasswordLength", 0) < 14:
            weaknesses.append("minimum length < 14")
        if not policy.get("RequireSymbols"):
            weaknesses.append("symbols not required")
        if not policy.get("RequireNumbers"):
            weaknesses.append("numbers not required")
        if not policy.get("RequireUppercaseCharacters"):
            weaknesses.append("uppercase not required")
        if not policy.get("RequireLowercaseCharacters"):
            weaknesses.append("lowercase not required")
        if weaknesses:
            findings.append(make_finding(
                "IAM-005",
                "Weak IAM Password Policy",
                "Medium",
                "CIS AWS 1.8 / NIST IA-5",
                "account-password-policy",
                "The account password policy is weak: " + ", ".join(weaknesses) + ".",
                "Set a password policy requiring at least 14 characters and a "
                "mix of upper/lowercase, numbers and symbols.",
            ))
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchEntity":
            findings.append(make_finding(
                "IAM-005",
                "No IAM Password Policy Configured",
                "Medium",
                "CIS AWS 1.8 / NIST IA-5",
                "account-password-policy",
                "No account password policy is configured, so IAM users may "
                "set weak passwords.",
                "Configure an account password policy enforcing complexity, "
                "rotation and reuse-prevention requirements.",
            ))
        else:
            raise

    return findings


def _older_than_days(timestamp, days):
    """Return True if an ISO8601 timestamp is older than ``days`` days."""
    from datetime import datetime, timezone
    if not timestamp or timestamp in ("N/A", "no_information", "not_supported"):
        return False
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return False
    age = datetime.now(timezone.utc) - dt
    return age.days > days

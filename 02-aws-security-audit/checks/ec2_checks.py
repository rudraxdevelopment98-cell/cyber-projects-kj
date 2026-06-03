"""EC2 / VPC-focused audit checks: open security groups and EBS encryption."""

from botocore.exceptions import ClientError

from .finding import make_finding

# Ports that are especially dangerous to expose to the whole internet.
_SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
}

_OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def run(session):
    ec2 = session.client("ec2")
    findings = []

    # --- EC2-001: Security group allows unrestricted access to sensitive ports ---
    try:
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
    except ClientError:
        sgs = []

    for sg in sgs:
        sg_id = sg["GroupId"]
        for perm in sg.get("IpPermissions", []):
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")
            open_ranges = [r for r in perm.get("IpRanges", [])
                           if r.get("CidrIp") in _OPEN_CIDRS]
            open_ranges += [r for r in perm.get("Ipv6Ranges", [])
                            if r.get("CidrIpv6") in _OPEN_CIDRS]
            if not open_ranges:
                continue

            for port, service in _SENSITIVE_PORTS.items():
                # from_port is None for "all traffic" rules.
                if from_port is None or (from_port <= port <= to_port):
                    findings.append(make_finding(
                        "EC2-001",
                        f"Security Group Allows Unrestricted {service} Access",
                        "High",
                        "CIS AWS 5.2 / NIST SC-7",
                        sg_id,
                        f"Security group '{sg_id}' permits inbound {service} "
                        f"(port {port}) from {open_ranges[0].get('CidrIp') or open_ranges[0].get('CidrIpv6')}. "
                        "Exposing management/database ports to the entire "
                        "internet invites brute-force and exploitation.",
                        f"Restrict the {service} rule to specific trusted CIDRs "
                        "or a bastion/SSM Session Manager. Remove the "
                        "0.0.0.0/0 ingress rule.",
                    ))

    # --- EC2-002: EBS encryption-by-default disabled (NIST SC-28) ---
    try:
        if not ec2.get_ebs_encryption_by_default().get("EbsEncryptionByDefault"):
            findings.append(make_finding(
                "EC2-002",
                "EBS Encryption By Default Disabled",
                "Medium",
                "CIS AWS 2.2.1 / NIST SC-28",
                "ebs-encryption-by-default",
                "EBS encryption by default is disabled in this region, so new "
                "volumes may be created unencrypted.",
                "Enable 'EBS encryption by default' in the EC2 console (Account "
                "Attributes) or via enable-ebs-encryption-by-default per region.",
            ))
    except ClientError:
        pass

    # --- EC2-003: Default security group allows traffic (CIS 5.4) ---
    for sg in sgs:
        if sg.get("GroupName") == "default":
            if sg.get("IpPermissions"):
                findings.append(make_finding(
                    "EC2-003",
                    "Default Security Group Allows Inbound Traffic",
                    "Low",
                    "CIS AWS 5.4 / NIST SC-7",
                    sg["GroupId"],
                    f"The default security group '{sg['GroupId']}' has inbound "
                    "rules. The default SG should deny all traffic and remain "
                    "unused.",
                    "Remove all inbound/outbound rules from the default "
                    "security group and assign workloads to purpose-built SGs.",
                ))

    return findings

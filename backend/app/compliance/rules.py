"""
Policy-as-Code Compliance Rules
Maps security checks to ISO 27001 and NIST 800-53 controls
"""
from typing import Dict, List, Any, Callable, Optional
from dataclasses import dataclass, field


@dataclass
class ComplianceRule:
    """A single compliance rule mapped to standards"""
    rule_id: str
    title: str
    description: str
    resource_type: str  # s3_bucket, ec2_instance, iam_user, etc.
    severity: str  # critical, high, medium, low
    control_framework: str  # ISO27001, NIST800-53, or BOTH
    iso_control: Optional[str] = None  # e.g., A.10.1.1
    nist_control: Optional[str] = None  # e.g., SC-28
    check_key: str = ""  # Key used to identify this check
    remediation: str = ""
    tags: List[str] = field(default_factory=list)


# ==================== S3 BUCKET RULES ====================

S3_RULES = [
    ComplianceRule(
        rule_id="S3-001",
        title="S3 Encryption at Rest",
        description="S3 bucket must have server-side encryption enabled (AES-256 or AWS KMS)",
        resource_type="s3_bucket",
        severity="high",
        control_framework="BOTH",
        iso_control="A.10.1.1",
        nist_control="SC-28",
        check_key="encryption_at_rest",
        remediation="Enable AES-256 (SSE-S3) or AWS KMS (SSE-KMS) server-side encryption on the bucket",
        tags=["encryption", "data-protection"]
    ),
    ComplianceRule(
        rule_id="S3-002",
        title="S3 Encryption in Transit",
        description="S3 bucket policy must enforce SSL/TLS for data in transit",
        resource_type="s3_bucket",
        severity="high",
        control_framework="BOTH",
        iso_control="A.14.1.2",
        nist_control="SC-8",
        check_key="encryption_in_transit",
        remediation="Add bucket policy denying requests without aws:SecureTransport condition",
        tags=["encryption", "network-security"]
    ),
    ComplianceRule(
        rule_id="S3-003",
        title="S3 Versioning Enabled",
        description="S3 bucket must have versioning enabled for data recovery and integrity",
        resource_type="s3_bucket",
        severity="medium",
        control_framework="BOTH",
        iso_control="A.12.3.1",
        nist_control="CP-9",
        check_key="versioning",
        remediation="Enable bucket versioning to protect against accidental deletion and overwrites",
        tags=["backup", "data-integrity"]
    ),
    ComplianceRule(
        rule_id="S3-004",
        title="S3 Public Access Block",
        description="S3 bucket must block all public access to prevent data exposure",
        resource_type="s3_bucket",
        severity="critical",
        control_framework="BOTH",
        iso_control="A.9.4.1",
        nist_control="AC-3",
        check_key="public_access_block",
        remediation="Enable BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets",
        tags=["access-control", "data-exposure"]
    ),
    ComplianceRule(
        rule_id="S3-005",
        title="S3 Access Logging",
        description="S3 bucket must have server access logging enabled for audit trail",
        resource_type="s3_bucket",
        severity="medium",
        control_framework="BOTH",
        iso_control="A.12.4.1",
        nist_control="AU-2",
        check_key="access_logging",
        remediation="Enable server access logging and direct logs to a dedicated logging bucket",
        tags=["logging", "audit"]
    ),
    ComplianceRule(
        rule_id="S3-006",
        title="S3 MFA Delete",
        description="S3 bucket should require MFA for object deletion to prevent unauthorized removal",
        resource_type="s3_bucket",
        severity="medium",
        control_framework="BOTH",
        iso_control="A.9.4.2",
        nist_control="IA-2",
        check_key="mfa_delete",
        remediation="Enable MFA Delete on the bucket versioning configuration",
        tags=["authentication", "data-protection"]
    ),
    ComplianceRule(
        rule_id="S3-007",
        title="S3 Lifecycle Policy",
        description="S3 bucket should have lifecycle policy for data retention and cost management",
        resource_type="s3_bucket",
        severity="low",
        control_framework="BOTH",
        iso_control="A.8.3.2",
        nist_control="MP-6",
        check_key="lifecycle_policy",
        remediation="Configure lifecycle rules for transitioning or expiring objects",
        tags=["data-retention", "cost-management"]
    ),
    ComplianceRule(
        rule_id="S3-008",
        title="S3 Bucket Policy Restrictions",
        description="S3 bucket policy must follow least-privilege principle with no wildcard principals",
        resource_type="s3_bucket",
        severity="high",
        control_framework="BOTH",
        iso_control="A.9.1.2",
        nist_control="AC-6",
        check_key="bucket_policy_restrictions",
        remediation="Remove wildcard (*) principals from bucket policy and use specific IAM roles/users",
        tags=["access-control", "least-privilege"]
    ),
]

# ==================== EC2 INSTANCE RULES ====================

EC2_RULES = [
    ComplianceRule(
        rule_id="EC2-001",
        title="Security Group - No Unrestricted Ingress",
        description="Security groups must not allow unrestricted inbound access (0.0.0.0/0) on sensitive ports",
        resource_type="ec2_instance",
        severity="critical",
        control_framework="BOTH",
        iso_control="A.13.1.1",
        nist_control="SC-7",
        check_key="security_group_ingress",
        remediation="Restrict security group inbound rules to specific IP ranges and required ports only",
        tags=["network-security", "firewall"]
    ),
    ComplianceRule(
        rule_id="EC2-002",
        title="IMDSv2 Required",
        description="EC2 instances must require IMDSv2 (token-based) to prevent SSRF-based credential theft",
        resource_type="ec2_instance",
        severity="high",
        control_framework="BOTH",
        iso_control="A.9.4.4",
        nist_control="AC-17",
        check_key="imdsv2_required",
        remediation="Set metadata_options http_tokens to 'required' to enforce IMDSv2",
        tags=["metadata-security", "credential-protection"]
    ),
    ComplianceRule(
        rule_id="EC2-003",
        title="EBS Volume Encryption",
        description="EBS volumes attached to EC2 instances must be encrypted at rest",
        resource_type="ec2_instance",
        severity="high",
        control_framework="BOTH",
        iso_control="A.10.1.1",
        nist_control="SC-28",
        check_key="ebs_encryption",
        remediation="Enable encryption on EBS volumes using AWS KMS or default encryption",
        tags=["encryption", "storage-security"]
    ),
]

# ==================== IAM RULES ====================

IAM_RULES = [
    ComplianceRule(
        rule_id="IAM-001",
        title="IAM MFA Enabled",
        description="IAM users with console access must have multi-factor authentication enabled",
        resource_type="iam_user",
        severity="critical",
        control_framework="BOTH",
        iso_control="A.9.4.2",
        nist_control="IA-2",
        check_key="mfa_enabled",
        remediation="Enable MFA for all IAM users with console access",
        tags=["authentication", "identity"]
    ),
    ComplianceRule(
        rule_id="IAM-002",
        title="No Wildcard Permissions",
        description="IAM policies must not grant wildcard (*) actions or resources",
        resource_type="iam_policy",
        severity="critical",
        control_framework="BOTH",
        iso_control="A.9.1.2",
        nist_control="AC-6",
        check_key="no_wildcard_permissions",
        remediation="Replace wildcard permissions with specific actions and resource ARNs following least privilege",
        tags=["access-control", "least-privilege"]
    ),
    ComplianceRule(
        rule_id="IAM-003",
        title="IAM Password Policy",
        description="Account password policy must enforce minimum length, complexity, and rotation",
        resource_type="iam_policy",
        severity="high",
        control_framework="BOTH",
        iso_control="A.9.4.3",
        nist_control="IA-5",
        check_key="password_policy",
        remediation="Configure password policy with minimum 14 characters, complexity requirements, and 90-day rotation",
        tags=["authentication", "password-security"]
    ),
]

# ==================== ALL RULES ====================

COMPLIANCE_RULES: List[ComplianceRule] = S3_RULES + EC2_RULES + IAM_RULES


def get_rules_by_framework(framework: str) -> List[ComplianceRule]:
    """Get rules for a specific framework (ISO27001, NIST800-53, BOTH)"""
    return [r for r in COMPLIANCE_RULES if r.control_framework in (framework, "BOTH")]


def get_rules_by_resource_type(resource_type: str) -> List[ComplianceRule]:
    """Get rules applicable to a specific resource type"""
    return [r for r in COMPLIANCE_RULES if r.resource_type == resource_type]


def get_rules_by_severity(severity: str) -> List[ComplianceRule]:
    """Get rules of a specific severity level"""
    return [r for r in COMPLIANCE_RULES if r.severity == severity]


def get_rule_by_id(rule_id: str) -> Optional[ComplianceRule]:
    """Get a specific rule by its ID"""
    for rule in COMPLIANCE_RULES:
        return next((r for r in COMPLIANCE_RULES if r.rule_id == rule_id), None)
    return None

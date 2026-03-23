"""
Enhanced Compliance Engine
Performs compliance checks mapped to ISO 27001 and NIST 800-53 controls
"""
from typing import Dict, List, Optional, Any
from datetime import datetime
from backend.app.compliance.rules import (
    ComplianceRule, COMPLIANCE_RULES,
    get_rules_by_resource_type, S3_RULES, EC2_RULES, IAM_RULES
)
from backend.app.models.schemas import ComplianceCheck, ComplianceResult


# Severity weights for scoring
SEVERITY_WEIGHTS = {
    "critical": 3.0,
    "high": 2.0,
    "medium": 1.0,
    "low": 0.5
}


class ComplianceEngine:
    """
    Policy-as-Code compliance engine with ISO 27001 & NIST 800-53 mappings.

    Evaluates cloud resources against predefined compliance rules and
    produces weighted compliance scores with control references.
    """

    def __init__(self):
        self.rules = COMPLIANCE_RULES

    # ------------------------------------------------------------------ #
    #  S3 Bucket Checks
    # ------------------------------------------------------------------ #

    def _check_s3_encryption_at_rest(self, config: Dict) -> bool:
        """Check if S3 bucket has encryption at rest enabled"""
        # Check Terraform config for server_side_encryption_configuration
        if "server_side_encryption_configuration" in str(config):
            return True
        if config.get("server_side_encryption_configuration"):
            return True
        # Check for encryption keyword indicators
        encryption = config.get("encryption", config.get("sse_algorithm"))
        if encryption:
            return True
        return False

    def _check_s3_encryption_in_transit(self, config: Dict) -> bool:
        """Check if bucket policy enforces SSL/TLS"""
        policy = config.get("policy", config.get("bucket_policy", ""))
        if isinstance(policy, dict):
            policy = str(policy)
        if "aws:SecureTransport" in str(policy):
            return True
        # Check for explicit ssl enforcement setting
        return config.get("enforce_ssl", False)

    def _check_s3_versioning(self, config: Dict) -> bool:
        """Check if bucket versioning is enabled"""
        versioning = config.get("versioning", {})
        if isinstance(versioning, dict):
            return versioning.get("enabled", False)
        if isinstance(versioning, list) and len(versioning) > 0:
            v = versioning[0] if isinstance(versioning[0], dict) else {}
            return v.get("enabled", False)
        return "versioning" in str(config) and "enabled" in str(config).lower()

    def _check_s3_public_access_block(self, config: Dict) -> bool:
        """Check if all public access is blocked"""
        # Look for aws_s3_bucket_public_access_block resource
        pab = config.get("public_access_block", config.get("block_public_access", {}))
        if isinstance(pab, dict):
            return all([
                pab.get("block_public_acls", False),
                pab.get("ignore_public_acls", False),
                pab.get("block_public_policy", False),
                pab.get("restrict_public_buckets", False)
            ])
        # Check for presence in Terraform config string
        cfg_str = str(config).lower()
        return "block_public_acls" in cfg_str and "restrict_public_buckets" in cfg_str

    def _check_s3_access_logging(self, config: Dict) -> bool:
        """Check if server access logging is enabled"""
        logging_conf = config.get("logging", config.get("access_logging", {}))
        if logging_conf:
            return True
        return "logging" in str(config).lower() and "target_bucket" in str(config).lower()

    def _check_s3_mfa_delete(self, config: Dict) -> bool:
        """Check if MFA delete is enabled"""
        versioning = config.get("versioning", {})
        if isinstance(versioning, dict):
            return versioning.get("mfa_delete", False)
        return "mfa_delete" in str(config).lower()

    def _check_s3_lifecycle_policy(self, config: Dict) -> bool:
        """Check if lifecycle policy exists"""
        lifecycle = config.get("lifecycle_rule", config.get("lifecycle", []))
        if lifecycle:
            return True
        return "lifecycle_rule" in str(config).lower()

    def _check_s3_bucket_policy_restrictions(self, config: Dict) -> bool:
        """Check bucket policy doesn't have wildcard principals"""
        policy = config.get("policy", config.get("bucket_policy", ""))
        policy_str = str(policy)
        # Fail if wildcard principal found
        if '"Principal": "*"' in policy_str or "'Principal': '*'" in policy_str:
            return False
        if '"Principal":"*"' in policy_str:
            return False
        # Pass if no policy (no overly permissive access)
        return True

    # ------------------------------------------------------------------ #
    #  EC2 Checks
    # ------------------------------------------------------------------ #

    def _check_ec2_security_group_ingress(self, config: Dict) -> bool:
        """Check security groups don't allow unrestricted ingress"""
        ingress = config.get("ingress", [])
        for rule in ingress:
            if isinstance(rule, dict):
                cidr = rule.get("cidr_blocks", [])
                if "0.0.0.0/0" in cidr:
                    port = rule.get("from_port", 0)
                    # Sensitive ports: SSH(22), RDP(3389), DB(3306,5432)
                    if port in [22, 3389, 3306, 5432, 0]:
                        return False
        cfg_str = str(config)
        if "0.0.0.0/0" in cfg_str and any(p in cfg_str for p in ["22", "3389"]):
            return False
        return True

    def _check_ec2_imdsv2(self, config: Dict) -> bool:
        """Check if IMDSv2 is required"""
        metadata = config.get("metadata_options", {})
        if isinstance(metadata, dict):
            return metadata.get("http_tokens") == "required"
        return "http_tokens" in str(config) and "required" in str(config)

    def _check_ec2_ebs_encryption(self, config: Dict) -> bool:
        """Check if EBS volumes are encrypted"""
        ebs = config.get("ebs_block_device", config.get("root_block_device", []))
        if isinstance(ebs, list):
            for vol in ebs:
                if isinstance(vol, dict) and not vol.get("encrypted", False):
                    return False
        return config.get("ebs_optimized", False) or "encrypted" in str(config).lower()

    # ------------------------------------------------------------------ #
    #  IAM Checks
    # ------------------------------------------------------------------ #

    def _check_iam_mfa(self, config: Dict) -> bool:
        """Check if MFA is enabled for IAM user"""
        return config.get("mfa_enabled", False) or "mfa" in str(config).lower()

    def _check_iam_no_wildcard(self, config: Dict) -> bool:
        """Check IAM policy doesn't use wildcard permissions"""
        policy = config.get("policy", config.get("policy_document", ""))
        policy_str = str(policy)
        if '"Action": "*"' in policy_str or '"Resource": "*"' in policy_str:
            if '"Effect": "Allow"' in policy_str:
                return False
        return True

    def _check_iam_password_policy(self, config: Dict) -> bool:
        """Check IAM password policy meets requirements"""
        min_length = config.get("minimum_password_length", 0)
        return min_length >= 14

    # ------------------------------------------------------------------ #
    #  Check Dispatcher
    # ------------------------------------------------------------------ #

    CHECK_FUNCTIONS = {
        "encryption_at_rest": "_check_s3_encryption_at_rest",
        "encryption_in_transit": "_check_s3_encryption_in_transit",
        "versioning": "_check_s3_versioning",
        "public_access_block": "_check_s3_public_access_block",
        "access_logging": "_check_s3_access_logging",
        "mfa_delete": "_check_s3_mfa_delete",
        "lifecycle_policy": "_check_s3_lifecycle_policy",
        "bucket_policy_restrictions": "_check_s3_bucket_policy_restrictions",
        "security_group_ingress": "_check_ec2_security_group_ingress",
        "imdsv2_required": "_check_ec2_imdsv2",
        "ebs_encryption": "_check_ec2_ebs_encryption",
        "mfa_enabled": "_check_iam_mfa",
        "no_wildcard_permissions": "_check_iam_no_wildcard",
        "password_policy": "_check_iam_password_policy",
    }

    def _run_check(self, rule: ComplianceRule, resource_config: Dict) -> ComplianceCheck:
        """Run a single compliance check against a resource configuration"""
        check_fn_name = self.CHECK_FUNCTIONS.get(rule.check_key)
        if not check_fn_name:
            return ComplianceCheck(
                status="SKIP",
                message=f"No check function for {rule.check_key}",
                severity=rule.severity,
                remediation=None
            )

        check_fn = getattr(self, check_fn_name, None)
        if not check_fn:
            return ComplianceCheck(
                status="SKIP",
                message=f"Check function not implemented: {check_fn_name}",
                severity=rule.severity,
                remediation=None
            )

        try:
            passed = check_fn(resource_config)
        except Exception as e:
            return ComplianceCheck(
                status="ERROR",
                message=f"Check failed with error: {str(e)}",
                severity=rule.severity,
                remediation=rule.remediation
            )

        control_ref = []
        if rule.iso_control:
            control_ref.append(f"ISO 27001 {rule.iso_control}")
        if rule.nist_control:
            control_ref.append(f"NIST 800-53 {rule.nist_control}")
        ref_str = " | ".join(control_ref)

        if passed:
            return ComplianceCheck(
                status="PASS",
                message=f"{rule.title} - Compliant [{ref_str}]",
                severity=rule.severity,
                remediation=None
            )
        else:
            return ComplianceCheck(
                status="FAIL",
                message=f"{rule.title} - Non-compliant [{ref_str}]",
                severity=rule.severity,
                remediation=f"[{rule.rule_id}] {rule.remediation}"
            )

    # ------------------------------------------------------------------ #
    #  Public API
    # ------------------------------------------------------------------ #

    def scan_resource(
        self,
        resource_type: str,
        resource_name: str,
        resource_config: Dict
    ) -> ComplianceResult:
        """
        Scan a single resource against all applicable compliance rules.

        Args:
            resource_type: Type of resource (s3_bucket, ec2_instance, iam_user, iam_policy)
            resource_name: Name/identifier of the resource
            resource_config: Configuration dictionary of the resource

        Returns:
            ComplianceResult with weighted compliance score
        """
        applicable_rules = get_rules_by_resource_type(resource_type)
        checks: Dict[str, ComplianceCheck] = {}

        for rule in applicable_rules:
            check_result = self._run_check(rule, resource_config)
            checks[rule.check_key] = check_result

        # Calculate weighted compliance score
        total_weight = 0.0
        passed_weight = 0.0
        for rule in applicable_rules:
            check = checks.get(rule.check_key)
            if check and check.status not in ("SKIP", "ERROR"):
                weight = SEVERITY_WEIGHTS.get(rule.severity, 1.0)
                total_weight += weight
                if check.status == "PASS":
                    passed_weight += weight

        compliance_score = (passed_weight / total_weight * 100) if total_weight > 0 else 0.0

        # Generate recommendations
        recommendations = []
        for rule in applicable_rules:
            check = checks.get(rule.check_key)
            if check and check.status == "FAIL" and check.remediation:
                recommendations.append(check.remediation)

        passed_count = sum(1 for c in checks.values() if c.status == "PASS")
        total_count = sum(1 for c in checks.values() if c.status not in ("SKIP", "ERROR"))

        return ComplianceResult(
            resource_name=resource_name,
            resource_type=resource_type,
            compliance_score=round(compliance_score, 2),
            checks=checks,
            summary=f"{passed_count}/{total_count} checks passed (weighted score: {round(compliance_score, 1)}%)",
            recommendations=recommendations
        )

    def scan_terraform(self, parsed_tf: Dict) -> List[ComplianceResult]:
        """
        Scan all resources in a parsed Terraform configuration.

        Args:
            parsed_tf: Parsed Terraform HCL2 configuration

        Returns:
            List of ComplianceResult for each resource found
        """
        results = []
        resources = parsed_tf.get("resource", [])

        for resource_block in resources:
            if isinstance(resource_block, dict):
                for resource_type, instances in resource_block.items():
                    mapped_type = self._map_tf_resource_type(resource_type)
                    if mapped_type and isinstance(instances, dict):
                        for name, config in instances.items():
                            if isinstance(config, dict):
                                result = self.scan_resource(mapped_type, name, config)
                                results.append(result)

        return results

    def _map_tf_resource_type(self, tf_type: str) -> Optional[str]:
        """Map Terraform resource type to our internal type"""
        mapping = {
            "aws_s3_bucket": "s3_bucket",
            "aws_instance": "ec2_instance",
            "aws_security_group": "ec2_instance",
            "aws_iam_user": "iam_user",
            "aws_iam_policy": "iam_policy",
            "aws_iam_role_policy": "iam_policy",
        }
        return mapping.get(tf_type)

    def get_framework_summary(self, results: List[ComplianceResult]) -> Dict:
        """Generate a summary of compliance by framework"""
        iso_checks = {"pass": 0, "fail": 0, "total": 0}
        nist_checks = {"pass": 0, "fail": 0, "total": 0}

        for result in results:
            for check_key, check in result.checks.items():
                if check.status in ("SKIP", "ERROR"):
                    continue
                # Find corresponding rule
                rule = next((r for r in COMPLIANCE_RULES if r.check_key == check_key), None)
                if rule:
                    if rule.iso_control:
                        iso_checks["total"] += 1
                        if check.status == "PASS":
                            iso_checks["pass"] += 1
                        else:
                            iso_checks["fail"] += 1
                    if rule.nist_control:
                        nist_checks["total"] += 1
                        if check.status == "PASS":
                            nist_checks["pass"] += 1
                        else:
                            nist_checks["fail"] += 1

        return {
            "ISO_27001": {
                **iso_checks,
                "score": round(iso_checks["pass"] / iso_checks["total"] * 100, 2) if iso_checks["total"] > 0 else 0
            },
            "NIST_800_53": {
                **nist_checks,
                "score": round(nist_checks["pass"] / nist_checks["total"] * 100, 2) if nist_checks["total"] > 0 else 0
            }
        }


# Global engine instance
compliance_engine = ComplianceEngine()

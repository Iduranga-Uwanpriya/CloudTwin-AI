"""
Compliance Checking Engine
Runs security and compliance checks on AWS resources against ISO 27001 & NIST 800-53 controls
"""
from backend.app.services.digital_twin import get_s3_client
from backend.app.models.schemas import ComplianceResult
from backend.app.compliance.engine import compliance_engine
from datetime import datetime


def check_bucket_compliance(bucket_name: str) -> ComplianceResult:
    """
    Run all compliance checks on S3 bucket against ISO 27001 & NIST 800-53 controls.

    Args:
        bucket_name: Name of bucket to check

    Returns:
        ComplianceResult: Complete compliance assessment with control references
    """
    s3_client = get_s3_client()
    resource_config = _get_bucket_config(s3_client, bucket_name)

    result = compliance_engine.scan_resource(
        resource_type="s3_bucket",
        resource_name=bucket_name,
        resource_config=resource_config
    )
    return result


def _get_bucket_config(s3_client, bucket_name: str) -> dict:
    """
    Query LocalStack/AWS to build a configuration dict for the bucket.
    This dict is then evaluated against compliance rules.
    """
    config = {"bucket_name": bucket_name}

    # Check encryption
    try:
        enc = s3_client.get_bucket_encryption(Bucket=bucket_name)
        rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        if rules:
            config["server_side_encryption_configuration"] = rules
            sse = rules[0].get("ApplyServerSideEncryptionByDefault", {})
            config["sse_algorithm"] = sse.get("SSEAlgorithm", "")
    except Exception:
        pass

    # Check versioning
    try:
        ver = s3_client.get_bucket_versioning(Bucket=bucket_name)
        versioning_status = ver.get("Status", "")
        mfa_delete = ver.get("MFADelete", "Disabled")
        config["versioning"] = {
            "enabled": versioning_status == "Enabled",
            "mfa_delete": mfa_delete == "Enabled"
        }
    except Exception:
        config["versioning"] = {"enabled": False, "mfa_delete": False}

    # Check public access block
    try:
        pab = s3_client.get_public_access_block(Bucket=bucket_name)
        pab_config = pab.get("PublicAccessBlockConfiguration", {})
        config["public_access_block"] = {
            "block_public_acls": pab_config.get("BlockPublicAcls", False),
            "ignore_public_acls": pab_config.get("IgnorePublicAcls", False),
            "block_public_policy": pab_config.get("BlockPublicPolicy", False),
            "restrict_public_buckets": pab_config.get("RestrictPublicBuckets", False),
        }
    except Exception:
        config["public_access_block"] = {}

    # Check bucket policy
    try:
        policy = s3_client.get_bucket_policy(Bucket=bucket_name)
        config["policy"] = policy.get("Policy", "")
    except Exception:
        config["policy"] = ""

    # Check logging
    try:
        logging_conf = s3_client.get_bucket_logging(Bucket=bucket_name)
        if logging_conf.get("LoggingEnabled"):
            config["logging"] = logging_conf["LoggingEnabled"]
    except Exception:
        pass

    # Check lifecycle
    try:
        lifecycle = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        if lifecycle.get("Rules"):
            config["lifecycle_rule"] = lifecycle["Rules"]
    except Exception:
        pass

    return config


def check_terraform_compliance(parsed_tf: dict) -> list:
    """
    Run compliance checks on a parsed Terraform configuration.

    Args:
        parsed_tf: Parsed Terraform HCL2 configuration

    Returns:
        List of ComplianceResult for each resource
    """
    return compliance_engine.scan_terraform(parsed_tf)

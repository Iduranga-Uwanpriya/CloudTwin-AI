"""
Live AWS Scanner — assumes cross-account role and inventories resources.

Uses STS AssumeRole with ExternalId for secure cross-account access.
Only reads resources, never modifies anything.
"""
import time
from datetime import datetime, timezone
from typing import Optional

import boto3
from botocore.exceptions import ClientError

from backend.app.db.models import AwsAccount


def get_aws_session(account: AwsAccount, region: str = None) -> boto3.Session:
    """
    Assume the cross-account IAM role and return a boto3 session
    with temporary credentials. Never stores credentials.
    """
    import os
    if region is None:
        region = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    sts = boto3.client("sts")
    assumed = sts.assume_role(
        RoleArn=account.role_arn,
        RoleSessionName=f"cloudtwin-scan-{account.id[:8]}",
        ExternalId=account.external_id,
        DurationSeconds=3600,
    )
    creds = assumed["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )


def scan_aws_account(account: AwsAccount, region: str = None) -> dict:
    """
    Full scan of an AWS account. Returns inventory + compliance-ready resource configs.
    """
    import os
    start = time.time()
    if region is None:
        region = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    session = get_aws_session(account, region)
    results = {
        "account_id": account.aws_account_id,
        "region": region,
        "resources": {},
        "errors": [],
    }

    # Scan each resource type, catch individual failures
    scanners = [
        ("s3", _scan_s3),
        ("ec2", _scan_ec2),
        ("iam", _scan_iam),
        ("security_groups", _scan_security_groups),
        ("vpc", _scan_vpc),
        ("rds", _scan_rds),
    ]

    for resource_type, scanner_fn in scanners:
        try:
            results["resources"][resource_type] = scanner_fn(session)
        except ClientError as e:
            results["errors"].append({
                "resource_type": resource_type,
                "error": str(e),
            })
        except Exception as e:
            results["errors"].append({
                "resource_type": resource_type,
                "error": f"Unexpected error: {str(e)}",
            })

    results["scan_duration_seconds"] = round(time.time() - start, 2)
    results["total_resources"] = sum(len(v) for v in results["resources"].values())

    return results


# ─────────────────────────── S3 ───────────────────────────

def _scan_s3(session: boto3.Session) -> list[dict]:
    s3 = session.client("s3")
    buckets = s3.list_buckets().get("Buckets", [])
    resources = []

    for bucket in buckets:
        name = bucket["Name"]
        config = {"name": name, "created": str(bucket.get("CreationDate", ""))}

        # Versioning
        try:
            v = s3.get_bucket_versioning(Bucket=name)
            config["versioning"] = v.get("Status", "Disabled")
        except Exception:
            config["versioning"] = "Unknown"

        # Encryption
        try:
            enc = s3.get_bucket_encryption(Bucket=name)
            config["encryption"] = True
            config["encryption_rules"] = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        except ClientError as e:
            if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                config["encryption"] = False
            else:
                config["encryption"] = "Unknown"

        # Public access block
        try:
            pab = s3.get_public_access_block(Bucket=name)
            config["public_access_block"] = pab.get("PublicAccessBlockConfiguration", {})
        except ClientError:
            config["public_access_block"] = None

        # Logging
        try:
            log = s3.get_bucket_logging(Bucket=name)
            config["logging"] = bool(log.get("LoggingEnabled"))
        except Exception:
            config["logging"] = False

        # ACL
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            grants = acl.get("Grants", [])
            config["public_acl"] = any(
                g.get("Grantee", {}).get("URI", "") == "http://acs.amazonaws.com/groups/global/AllUsers"
                for g in grants
            )
        except Exception:
            config["public_acl"] = False

        resources.append(config)

    return resources


# ─────────────────────────── EC2 ───────────────────────────

def _scan_ec2(session: boto3.Session) -> list[dict]:
    ec2 = session.client("ec2")
    instances = []
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate():
        for reservation in page.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                instances.append({
                    "instance_id": inst["InstanceId"],
                    "state": inst["State"]["Name"],
                    "instance_type": inst.get("InstanceType"),
                    "public_ip": inst.get("PublicIpAddress"),
                    "private_ip": inst.get("PrivateIpAddress"),
                    "iam_profile": inst.get("IamInstanceProfile", {}).get("Arn"),
                    "monitoring": inst.get("Monitoring", {}).get("State"),
                    "ebs_optimized": inst.get("EbsOptimized", False),
                    "security_groups": [sg["GroupId"] for sg in inst.get("SecurityGroups", [])],
                    "tags": {t["Key"]: t["Value"] for t in inst.get("Tags", [])},
                })
    return instances


# ─────────────────────────── IAM ───────────────────────────

def _scan_iam(session: boto3.Session) -> list[dict]:
    iam = session.client("iam")
    users = []
    for user in iam.list_users().get("Users", []):
        username = user["UserName"]
        u = {
            "username": username,
            "arn": user["Arn"],
            "created": str(user.get("CreateDate", "")),
            "password_last_used": str(user.get("PasswordLastUsed", "")),
        }

        # MFA
        try:
            mfa = iam.list_mfa_devices(UserName=username)
            u["mfa_enabled"] = len(mfa.get("MFADevices", [])) > 0
        except Exception:
            u["mfa_enabled"] = False

        # Access keys
        try:
            keys = iam.list_access_keys(UserName=username)
            u["access_keys"] = [
                {
                    "id": k["AccessKeyId"],
                    "status": k["Status"],
                    "created": str(k.get("CreateDate", "")),
                }
                for k in keys.get("AccessKeyMetadata", [])
            ]
        except Exception:
            u["access_keys"] = []

        # Inline policies
        try:
            policies = iam.list_user_policies(UserName=username)
            u["inline_policies"] = policies.get("PolicyNames", [])
        except Exception:
            u["inline_policies"] = []

        users.append(u)

    return users


# ─────────────────────────── Security Groups ───────────────────────────

def _scan_security_groups(session: boto3.Session) -> list[dict]:
    ec2 = session.client("ec2")
    sgs = ec2.describe_security_groups().get("SecurityGroups", [])
    results = []
    for sg in sgs:
        open_ingress = []
        for rule in sg.get("IpPermissions", []):
            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    open_ingress.append({
                        "protocol": rule.get("IpProtocol", "all"),
                        "from_port": rule.get("FromPort"),
                        "to_port": rule.get("ToPort"),
                    })
        results.append({
            "group_id": sg["GroupId"],
            "group_name": sg.get("GroupName"),
            "vpc_id": sg.get("VpcId"),
            "description": sg.get("Description"),
            "open_to_world": len(open_ingress) > 0,
            "open_ingress_rules": open_ingress,
        })
    return results


# ─────────────────────────── VPC ───────────────────────────

def _scan_vpc(session: boto3.Session) -> list[dict]:
    ec2 = session.client("ec2")
    vpcs = ec2.describe_vpcs().get("Vpcs", [])
    results = []
    for vpc in vpcs:
        vpc_id = vpc["VpcId"]
        v = {
            "vpc_id": vpc_id,
            "cidr_block": vpc.get("CidrBlock"),
            "is_default": vpc.get("IsDefault", False),
            "state": vpc.get("State"),
            "tags": {t["Key"]: t["Value"] for t in vpc.get("Tags", [])},
        }

        # Flow logs
        try:
            fl = ec2.describe_flow_logs(Filters=[{"Name": "resource-id", "Values": [vpc_id]}])
            v["flow_logs_enabled"] = len(fl.get("FlowLogs", [])) > 0
        except Exception:
            v["flow_logs_enabled"] = False

        results.append(v)

    return results


# ─────────────────────────── RDS ───────────────────────────

def _scan_rds(session: boto3.Session) -> list[dict]:
    rds = session.client("rds")
    instances = rds.describe_db_instances().get("DBInstances", [])
    results = []
    for db in instances:
        results.append({
            "db_instance_id": db["DBInstanceIdentifier"],
            "engine": db.get("Engine"),
            "engine_version": db.get("EngineVersion"),
            "instance_class": db.get("DBInstanceClass"),
            "storage_encrypted": db.get("StorageEncrypted", False),
            "publicly_accessible": db.get("PubliclyAccessible", False),
            "multi_az": db.get("MultiAZ", False),
            "backup_retention": db.get("BackupRetentionPeriod", 0),
            "auto_minor_upgrade": db.get("AutoMinorVersionUpgrade", False),
        })
    return results

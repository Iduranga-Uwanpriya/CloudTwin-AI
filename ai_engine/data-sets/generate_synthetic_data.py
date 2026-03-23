"""
Synthetic Data Generator for CloudTwin AI
==========================================
Generates realistic AWS CloudTrail logs and VPC Flow Logs for ML model training.
Anomalous events (~5%) are injected with realistic attack patterns including
privilege escalation, unusual access times, data exfiltration, and port scanning.

Usage:
    python generate_synthetic_data.py [--cloudtrail-rows 500] [--vpc-rows 300]
                                      [--anomaly-rate 0.05] [--seed 42]
                                      [--output-dir .]
"""

import argparse
import csv
import os
import random
from datetime import datetime, timedelta, timezone


# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

NORMAL_API_CALLS = {
    "s3.amazonaws.com": [
        "GetObject", "PutObject", "ListBuckets", "ListObjects",
        "HeadObject", "CopyObject", "GetBucketLocation",
    ],
    "iam.amazonaws.com": [
        "GetUser", "ListUsers", "GetRole", "ListRoles",
        "GetPolicy", "ListPolicies", "GetGroup",
    ],
    "ec2.amazonaws.com": [
        "DescribeInstances", "DescribeSecurityGroups", "DescribeVpcs",
        "DescribeSubnets", "DescribeImages", "DescribeVolumes",
    ],
    "lambda.amazonaws.com": [
        "ListFunctions", "GetFunction", "Invoke",
    ],
    "sts.amazonaws.com": [
        "GetCallerIdentity", "AssumeRole",
    ],
    "cloudwatch.amazonaws.com": [
        "GetMetricData", "ListMetrics", "DescribeAlarms",
    ],
    "dynamodb.amazonaws.com": [
        "GetItem", "PutItem", "Query", "Scan", "DescribeTable",
    ],
}

ANOMALOUS_API_CALLS = {
    "s3.amazonaws.com": [
        "DeleteBucket", "PutBucketPolicy", "PutBucketAcl",
        "DeleteObject", "PutBucketPublicAccessBlock",
    ],
    "iam.amazonaws.com": [
        "CreateUser", "AttachUserPolicy", "CreateAccessKey",
        "PutUserPolicy", "CreateLoginProfile", "AddUserToGroup",
        "AttachRolePolicy", "CreateRole", "UpdateAssumeRolePolicy",
    ],
    "ec2.amazonaws.com": [
        "RunInstances", "AuthorizeSecurityGroupIngress",
        "CreateKeyPair", "ModifyInstanceAttribute",
        "StopInstances", "TerminateInstances",
    ],
    "lambda.amazonaws.com": [
        "CreateFunction", "UpdateFunctionCode", "AddPermission",
    ],
    "sts.amazonaws.com": [
        "AssumeRoleWithSAML", "GetFederationToken",
    ],
}

NORMAL_USERS = [
    "arn:aws:iam::123456789012:user/developer-alice",
    "arn:aws:iam::123456789012:user/developer-bob",
    "arn:aws:iam::123456789012:user/developer-carol",
    "arn:aws:iam::123456789012:user/ops-dave",
    "arn:aws:iam::123456789012:user/ops-erin",
    "arn:aws:iam::123456789012:user/analyst-frank",
    "arn:aws:iam::123456789012:role/lambda-execution-role",
    "arn:aws:iam::123456789012:role/ecs-task-role",
    "arn:aws:iam::123456789012:role/ci-cd-pipeline-role",
]

SUSPICIOUS_USERS = [
    "arn:aws:iam::123456789012:root",
    "arn:aws:iam::123456789012:user/temp-contractor-99",
    "arn:aws:iam::123456789012:user/test-admin",
    "arn:aws:iam::987654321098:user/external-user",
]

NORMAL_IPS = [
    "10.0.1.15", "10.0.1.22", "10.0.1.33", "10.0.2.10", "10.0.2.45",
    "10.0.3.8", "10.0.3.19", "172.16.0.5", "172.16.0.12", "172.16.1.7",
    "52.94.76.10", "54.239.28.85",  # AWS service IPs
    "192.168.1.100", "192.168.1.101", "192.168.1.102",
]

SUSPICIOUS_IPS = [
    "198.51.100.77", "203.0.113.42", "91.134.210.15", "185.220.101.33",
    "45.33.32.156", "104.248.50.87", "178.128.200.15", "139.59.100.22",
]

REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]
UNUSUAL_REGIONS = ["ap-northeast-3", "sa-east-1", "af-south-1", "me-south-1"]

ERROR_CODES_NORMAL = ["", "", "", "", "", "", "", "", "", "ThrottlingException"]
ERROR_CODES_ANOMALOUS = [
    "AccessDenied", "UnauthorizedAccess", "AccessDenied",
    "Client.UnauthorizedAccess", "AccessDenied", "",
]

# VPC Flow Log constants
INTERNAL_SUBNETS = ["10.0.1", "10.0.2", "10.0.3", "172.16.0", "172.16.1"]
COMMON_PORTS = [80, 443, 8080, 8443, 3306, 5432, 6379, 27017, 22, 53]
SUSPICIOUS_PORTS = [4444, 5555, 6666, 1337, 31337, 9001, 12345, 23, 445, 135]


# ---------------------------------------------------------------------------
# CloudTrail generator
# ---------------------------------------------------------------------------

def generate_cloudtrail_logs(num_rows=500, anomaly_rate=0.05, seed=42):
    """Generate synthetic CloudTrail log entries."""
    rng = random.Random(seed)
    num_anomalies = int(num_rows * anomaly_rate)
    num_normal = num_rows - num_anomalies

    # Anomaly indices (randomly placed)
    anomaly_indices = set(rng.sample(range(num_rows), num_anomalies))

    base_time = datetime(2025, 11, 1, 0, 0, 0, tzinfo=timezone.utc)
    rows = []

    for i in range(num_rows):
        is_anomaly = 1 if i in anomaly_indices else 0

        if is_anomaly:
            row = _generate_anomalous_cloudtrail_event(rng, base_time, i, num_rows)
        else:
            row = _generate_normal_cloudtrail_event(rng, base_time, i, num_rows)

        row["is_anomaly"] = is_anomaly
        rows.append(row)

    # Sort by event_time for realism
    rows.sort(key=lambda r: r["event_time"])
    return rows


def _generate_normal_cloudtrail_event(rng, base_time, index, total):
    """Create a single normal CloudTrail event."""
    # Spread events across ~30 days, mostly during business hours
    day_offset = int(index / total * 30)
    hour = rng.choice([9, 10, 11, 12, 13, 14, 15, 16, 17])
    minute = rng.randint(0, 59)
    second = rng.randint(0, 59)
    event_time = base_time + timedelta(
        days=day_offset, hours=hour, minutes=minute, seconds=second
    )

    source = rng.choice(list(NORMAL_API_CALLS.keys()))
    event_name = rng.choice(NORMAL_API_CALLS[source])
    source_ip = rng.choice(NORMAL_IPS)
    user_identity = rng.choice(NORMAL_USERS)
    region = rng.choice(REGIONS)
    error_code = rng.choice(ERROR_CODES_NORMAL)

    return {
        "event_time": event_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event_name": event_name,
        "event_source": source,
        "source_ip": source_ip,
        "user_identity": user_identity,
        "region": region,
        "error_code": error_code,
    }


def _generate_anomalous_cloudtrail_event(rng, base_time, index, total):
    """Create a single anomalous CloudTrail event with realistic attack patterns."""
    pattern = rng.choice([
        "odd_hours", "unusual_ip", "privilege_escalation",
        "rapid_calls", "cross_region", "root_access",
    ])

    day_offset = int(index / total * 30)
    event_time = base_time + timedelta(days=day_offset)

    if pattern == "odd_hours":
        # API calls at 2-5 AM
        hour = rng.randint(2, 5)
        event_time += timedelta(hours=hour, minutes=rng.randint(0, 59),
                                seconds=rng.randint(0, 59))
        source = rng.choice(list(NORMAL_API_CALLS.keys()))
        event_name = rng.choice(
            ANOMALOUS_API_CALLS.get(source, NORMAL_API_CALLS[source])
        )
        source_ip = rng.choice(NORMAL_IPS + SUSPICIOUS_IPS)
        user_identity = rng.choice(NORMAL_USERS)
        region = rng.choice(REGIONS)
        error_code = rng.choice(["", "AccessDenied"])

    elif pattern == "unusual_ip":
        hour = rng.randint(0, 23)
        event_time += timedelta(hours=hour, minutes=rng.randint(0, 59),
                                seconds=rng.randint(0, 59))
        source = rng.choice(list(ANOMALOUS_API_CALLS.keys()))
        event_name = rng.choice(ANOMALOUS_API_CALLS[source])
        source_ip = rng.choice(SUSPICIOUS_IPS)
        user_identity = rng.choice(NORMAL_USERS + SUSPICIOUS_USERS)
        region = rng.choice(REGIONS)
        error_code = rng.choice(ERROR_CODES_ANOMALOUS)

    elif pattern == "privilege_escalation":
        hour = rng.randint(8, 22)
        event_time += timedelta(hours=hour, minutes=rng.randint(0, 59),
                                seconds=rng.randint(0, 59))
        source = "iam.amazonaws.com"
        event_name = rng.choice([
            "AttachUserPolicy", "CreateAccessKey", "PutUserPolicy",
            "CreateLoginProfile", "AddUserToGroup", "AttachRolePolicy",
            "CreateRole", "UpdateAssumeRolePolicy",
        ])
        source_ip = rng.choice(SUSPICIOUS_IPS + NORMAL_IPS[:3])
        user_identity = rng.choice(SUSPICIOUS_USERS)
        region = "us-east-1"
        error_code = rng.choice(["", "AccessDenied", "AccessDenied"])

    elif pattern == "rapid_calls":
        # Burst of calls within seconds
        hour = rng.randint(0, 23)
        minute = rng.randint(0, 59)
        second = rng.randint(0, 55)
        event_time += timedelta(hours=hour, minutes=minute,
                                seconds=second + rng.uniform(0, 3))
        source = rng.choice(list(ANOMALOUS_API_CALLS.keys()))
        event_name = rng.choice(ANOMALOUS_API_CALLS[source])
        source_ip = rng.choice(SUSPICIOUS_IPS)
        user_identity = rng.choice(SUSPICIOUS_USERS)
        region = rng.choice(REGIONS)
        error_code = ""

    elif pattern == "cross_region":
        hour = rng.randint(8, 20)
        event_time += timedelta(hours=hour, minutes=rng.randint(0, 59),
                                seconds=rng.randint(0, 59))
        source = rng.choice(list(ANOMALOUS_API_CALLS.keys()))
        event_name = rng.choice(ANOMALOUS_API_CALLS[source])
        source_ip = rng.choice(SUSPICIOUS_IPS)
        user_identity = rng.choice(NORMAL_USERS)
        region = rng.choice(UNUSUAL_REGIONS)
        error_code = rng.choice(["", "AccessDenied"])

    else:  # root_access
        hour = rng.randint(0, 23)
        event_time += timedelta(hours=hour, minutes=rng.randint(0, 59),
                                seconds=rng.randint(0, 59))
        source = rng.choice(["iam.amazonaws.com", "s3.amazonaws.com"])
        event_name = rng.choice(
            ANOMALOUS_API_CALLS.get(source, ["DeleteBucket"])
        )
        source_ip = rng.choice(SUSPICIOUS_IPS)
        user_identity = "arn:aws:iam::123456789012:root"
        region = rng.choice(REGIONS + UNUSUAL_REGIONS)
        error_code = ""

    return {
        "event_time": event_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event_name": event_name,
        "event_source": source,
        "source_ip": source_ip,
        "user_identity": user_identity,
        "region": region,
        "error_code": error_code,
    }


# ---------------------------------------------------------------------------
# VPC Flow Log generator
# ---------------------------------------------------------------------------

def generate_vpc_flow_logs(num_rows=300, anomaly_rate=0.05, seed=42):
    """Generate synthetic VPC Flow Log entries."""
    rng = random.Random(seed + 1)  # different seed for variety
    num_anomalies = int(num_rows * anomaly_rate)
    num_normal = num_rows - num_anomalies
    anomaly_indices = set(rng.sample(range(num_rows), num_anomalies))

    base_time = datetime(2025, 11, 1, 0, 0, 0, tzinfo=timezone.utc)
    rows = []

    for i in range(num_rows):
        is_anomaly = 1 if i in anomaly_indices else 0

        if is_anomaly:
            row = _generate_anomalous_vpc_flow(rng, base_time, i, num_rows)
        else:
            row = _generate_normal_vpc_flow(rng, base_time, i, num_rows)

        row["is_anomaly"] = is_anomaly
        rows.append(row)

    rows.sort(key=lambda r: r["timestamp"])
    return rows


def _random_internal_ip(rng):
    subnet = rng.choice(INTERNAL_SUBNETS)
    return f"{subnet}.{rng.randint(2, 254)}"


def _generate_normal_vpc_flow(rng, base_time, index, total):
    """Create a single normal VPC flow log entry."""
    day_offset = int(index / total * 30)
    hour = rng.choice([8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18])
    ts = base_time + timedelta(
        days=day_offset, hours=hour,
        minutes=rng.randint(0, 59), seconds=rng.randint(0, 59)
    )

    src_ip = _random_internal_ip(rng)
    dst_ip = _random_internal_ip(rng)
    src_port = rng.randint(32768, 65535)  # ephemeral port
    dst_port = rng.choice(COMMON_PORTS)
    protocol = rng.choice(["TCP", "TCP", "TCP", "TCP", "UDP"])  # TCP-heavy
    bytes_transferred = rng.randint(64, 150000)
    packets = max(1, bytes_transferred // rng.randint(500, 1500))
    action = rng.choices(["ACCEPT", "REJECT"], weights=[95, 5])[0]

    return {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "bytes_transferred": bytes_transferred,
        "packets": packets,
        "action": action,
    }


def _generate_anomalous_vpc_flow(rng, base_time, index, total):
    """Create a single anomalous VPC flow log entry."""
    pattern = rng.choice([
        "large_transfer", "unusual_port", "high_packets",
        "repeated_reject", "external_exfil",
    ])

    day_offset = int(index / total * 30)
    ts = base_time + timedelta(
        days=day_offset, hours=rng.randint(0, 23),
        minutes=rng.randint(0, 59), seconds=rng.randint(0, 59)
    )

    if pattern == "large_transfer":
        src_ip = _random_internal_ip(rng)
        dst_ip = rng.choice(SUSPICIOUS_IPS)
        src_port = rng.randint(32768, 65535)
        dst_port = rng.choice([443, 8443, 8080])
        protocol = "TCP"
        bytes_transferred = rng.randint(500_000_000, 2_000_000_000)
        packets = bytes_transferred // rng.randint(1000, 1500)
        action = "ACCEPT"

    elif pattern == "unusual_port":
        src_ip = rng.choice(SUSPICIOUS_IPS)
        dst_ip = _random_internal_ip(rng)
        src_port = rng.randint(32768, 65535)
        dst_port = rng.choice(SUSPICIOUS_PORTS)
        protocol = "TCP"
        bytes_transferred = rng.randint(100, 50000)
        packets = max(1, bytes_transferred // rng.randint(500, 1500))
        action = rng.choice(["ACCEPT", "REJECT"])

    elif pattern == "high_packets":
        src_ip = rng.choice(SUSPICIOUS_IPS)
        dst_ip = _random_internal_ip(rng)
        src_port = rng.randint(32768, 65535)
        dst_port = rng.choice(COMMON_PORTS + SUSPICIOUS_PORTS)
        protocol = rng.choice(["TCP", "UDP"])
        packets = rng.randint(50000, 500000)
        bytes_transferred = packets * rng.randint(40, 100)  # small per-packet
        action = "ACCEPT"

    elif pattern == "repeated_reject":
        src_ip = rng.choice(SUSPICIOUS_IPS)
        dst_ip = _random_internal_ip(rng)
        src_port = rng.randint(32768, 65535)
        dst_port = rng.choice(COMMON_PORTS)
        protocol = "TCP"
        bytes_transferred = rng.randint(40, 200)
        packets = rng.randint(1, 5)
        action = "REJECT"

    else:  # external_exfil
        src_ip = _random_internal_ip(rng)
        dst_ip = rng.choice(SUSPICIOUS_IPS)
        src_port = rng.randint(32768, 65535)
        dst_port = rng.choice([53, 443, 8080])
        protocol = rng.choice(["TCP", "UDP"])
        bytes_transferred = rng.randint(10_000_000, 500_000_000)
        packets = bytes_transferred // rng.randint(800, 1500)
        action = "ACCEPT"

    return {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "bytes_transferred": bytes_transferred,
        "packets": packets,
        "action": action,
    }


# ---------------------------------------------------------------------------
# CSV writers
# ---------------------------------------------------------------------------

CLOUDTRAIL_FIELDS = [
    "event_time", "event_name", "event_source", "source_ip",
    "user_identity", "region", "error_code", "is_anomaly",
]

VPC_FLOW_FIELDS = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "bytes_transferred", "packets", "action", "is_anomaly",
]


def write_csv(filepath, fieldnames, rows):
    """Write rows to a CSV file."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"  Wrote {len(rows)} rows -> {filepath}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate synthetic CloudTrail and VPC Flow Log datasets."
    )
    parser.add_argument(
        "--cloudtrail-rows", type=int, default=500,
        help="Number of CloudTrail log rows (default: 500)",
    )
    parser.add_argument(
        "--vpc-rows", type=int, default=300,
        help="Number of VPC Flow Log rows (default: 300)",
    )
    parser.add_argument(
        "--anomaly-rate", type=float, default=0.05,
        help="Fraction of rows that are anomalous (default: 0.05)",
    )
    parser.add_argument(
        "--seed", type=int, default=42,
        help="Random seed for reproducibility (default: 42)",
    )
    parser.add_argument(
        "--output-dir", type=str, default=os.path.dirname(__file__) or ".",
        help="Output directory for CSV files (default: same dir as script)",
    )
    args = parser.parse_args()

    print("CloudTwin AI - Synthetic Data Generator")
    print("=" * 42)
    print(f"  CloudTrail rows : {args.cloudtrail_rows}")
    print(f"  VPC Flow rows   : {args.vpc_rows}")
    print(f"  Anomaly rate    : {args.anomaly_rate:.1%}")
    print(f"  Seed            : {args.seed}")
    print(f"  Output dir      : {args.output_dir}")
    print()

    # Generate CloudTrail logs
    print("Generating CloudTrail logs...")
    ct_rows = generate_cloudtrail_logs(
        num_rows=args.cloudtrail_rows,
        anomaly_rate=args.anomaly_rate,
        seed=args.seed,
    )
    ct_path = os.path.join(args.output_dir, "synthetic_cloudtrail_logs.csv")
    write_csv(ct_path, CLOUDTRAIL_FIELDS, ct_rows)
    ct_anomalies = sum(1 for r in ct_rows if r["is_anomaly"] == 1)
    print(f"  Anomalous events: {ct_anomalies}/{len(ct_rows)} "
          f"({ct_anomalies / len(ct_rows):.1%})")
    print()

    # Generate VPC Flow Logs
    print("Generating VPC Flow Logs...")
    vpc_rows = generate_vpc_flow_logs(
        num_rows=args.vpc_rows,
        anomaly_rate=args.anomaly_rate,
        seed=args.seed,
    )
    vpc_path = os.path.join(args.output_dir, "synthetic_vpc_flow_logs.csv")
    write_csv(vpc_path, VPC_FLOW_FIELDS, vpc_rows)
    vpc_anomalies = sum(1 for r in vpc_rows if r["is_anomaly"] == 1)
    print(f"  Anomalous events: {vpc_anomalies}/{len(vpc_rows)} "
          f"({vpc_anomalies / len(vpc_rows):.1%})")
    print()

    print("Done.")


if __name__ == "__main__":
    main()

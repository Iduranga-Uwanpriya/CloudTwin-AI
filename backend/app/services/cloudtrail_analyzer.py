"""
CloudTrail Threat Analyzer — rule-based detection of suspicious AWS API activity.

Pulls CloudTrail events via the existing cross-account role and applies
threat detection rules. No ML needed — known attack patterns.
"""
from datetime import datetime, timezone, timedelta
from collections import Counter
from typing import Optional

import boto3


# ── Threat Rules ──────────────────────────────────────────────

THREAT_RULES = [
    {
        "id": "CT-001",
        "title": "Root Account Usage",
        "description": "Root account was used for API calls. Root should only be used for initial setup.",
        "severity": "critical",
        "check": lambda e: (
            e.get("userIdentity", {}).get("type") == "Root"
            and e.get("eventName") not in ["ConsoleLogin"]
        ),
    },
    {
        "id": "CT-002",
        "title": "Root Console Login",
        "description": "Root account logged into the AWS Console. Use IAM users instead.",
        "severity": "critical",
        "check": lambda e: (
            e.get("userIdentity", {}).get("type") == "Root"
            and e.get("eventName") == "ConsoleLogin"
        ),
    },
    {
        "id": "CT-003",
        "title": "Console Login Without MFA",
        "description": "A user logged into the Console without Multi-Factor Authentication.",
        "severity": "high",
        "check": lambda e: (
            e.get("eventName") == "ConsoleLogin"
            and e.get("responseElements", {}).get("ConsoleLogin") == "Success"
            and not e.get("additionalEventData", {}).get("MFAUsed", "No") == "Yes"
        ),
    },
    {
        "id": "CT-004",
        "title": "Failed Console Login",
        "description": "Failed console login attempt — possible brute force.",
        "severity": "high",
        "check": lambda e: (
            e.get("eventName") == "ConsoleLogin"
            and e.get("responseElements", {}).get("ConsoleLogin") == "Failure"
        ),
    },
    {
        "id": "CT-005",
        "title": "IAM Policy Change",
        "description": "IAM policy was created, modified, or deleted.",
        "severity": "high",
        "check": lambda e: e.get("eventName") in [
            "CreatePolicy", "DeletePolicy", "CreatePolicyVersion",
            "AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy",
            "DetachUserPolicy", "DetachRolePolicy", "DetachGroupPolicy",
            "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy",
            "DeleteUserPolicy", "DeleteRolePolicy", "DeleteGroupPolicy",
        ],
    },
    {
        "id": "CT-006",
        "title": "IAM User/Role Creation",
        "description": "New IAM user, role, or access key was created.",
        "severity": "medium",
        "check": lambda e: e.get("eventName") in [
            "CreateUser", "CreateRole", "CreateAccessKey",
            "CreateLoginProfile", "CreateServiceLinkedRole",
        ],
    },
    {
        "id": "CT-007",
        "title": "Security Group Modified",
        "description": "Security group rules were changed — could expose resources.",
        "severity": "high",
        "check": lambda e: e.get("eventName") in [
            "AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
            "RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress",
            "CreateSecurityGroup", "DeleteSecurityGroup",
        ],
    },
    {
        "id": "CT-008",
        "title": "Bulk Resource Deletion",
        "description": "Resources were deleted — possible destructive action.",
        "severity": "high",
        "check": lambda e: e.get("eventName") in [
            "DeleteBucket", "DeleteDBInstance", "TerminateInstances",
            "DeleteVpc", "DeleteSubnet", "DeleteStack",
            "DeleteTable", "DeleteFunction", "DeleteCluster",
        ],
    },
    {
        "id": "CT-009",
        "title": "Access Denied (Unauthorized Attempt)",
        "description": "API call was denied — possible privilege escalation attempt.",
        "severity": "medium",
        "check": lambda e: (
            e.get("errorCode") in ["AccessDenied", "UnauthorizedAccess", "Client.UnauthorizedAccess"]
        ),
    },
    {
        "id": "CT-010",
        "title": "S3 Bucket Policy or ACL Changed",
        "description": "S3 bucket permissions were modified — could expose data publicly.",
        "severity": "critical",
        "check": lambda e: e.get("eventName") in [
            "PutBucketPolicy", "DeleteBucketPolicy",
            "PutBucketAcl", "PutBucketPublicAccessBlock",
            "DeleteBucketPublicAccessBlock",
        ],
    },
    {
        "id": "CT-011",
        "title": "CloudTrail Logging Modified",
        "description": "CloudTrail was stopped or modified — possible evidence tampering.",
        "severity": "critical",
        "check": lambda e: e.get("eventName") in [
            "StopLogging", "DeleteTrail", "UpdateTrail",
            "PutEventSelectors",
        ],
    },
    {
        "id": "CT-012",
        "title": "Encryption/KMS Key Modification",
        "description": "KMS key or encryption settings were changed.",
        "severity": "high",
        "check": lambda e: e.get("eventName") in [
            "DisableKey", "ScheduleKeyDeletion", "DeleteAlias",
            "PutKeyPolicy", "CreateGrant",
        ],
    },
]


# ── Analyzer ──────────────────────────────────────────────────

def analyze_cloudtrail(session: boto3.Session, hours: int = 24) -> dict:
    """
    Pull recent CloudTrail events and analyze for threats.

    Args:
        session: boto3 Session with cross-account credentials
        hours: How many hours of history to analyze (default 24)

    Returns:
        Dict with threats, stats, and event summary
    """
    client = session.client("cloudtrail")

    start_time = datetime.now(timezone.utc) - timedelta(hours=hours)
    end_time = datetime.now(timezone.utc)

    # Pull events
    events = []
    try:
        paginator = client.get_paginator("lookup_events")
        for page in paginator.paginate(
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=50,
        ):
            for event in page.get("Events", []):
                # Parse the CloudTrailEvent JSON
                import json
                try:
                    detail = json.loads(event.get("CloudTrailEvent", "{}"))
                except (json.JSONDecodeError, TypeError):
                    detail = {}

                events.append({
                    "event_id": event.get("EventId"),
                    "event_name": event.get("EventName"),
                    "event_time": str(event.get("EventTime", "")),
                    "username": event.get("Username", ""),
                    "source_ip": detail.get("sourceIPAddress", ""),
                    "user_agent": detail.get("userAgent", ""),
                    "aws_region": detail.get("awsRegion", ""),
                    "error_code": detail.get("errorCode"),
                    "error_message": detail.get("errorMessage"),
                    "resources": [r.get("ResourceName", "") for r in event.get("Resources", [])],
                    "_raw": detail,
                })
    except Exception as e:
        return {
            "status": "error",
            "error": f"Failed to fetch CloudTrail events: {str(e)}",
            "threats": [],
            "total_events": 0,
        }

    # Run threat rules
    threats = []
    for event in events:
        raw = event.get("_raw", {})
        for rule in THREAT_RULES:
            try:
                if rule["check"](raw):
                    threats.append({
                        "rule_id": rule["id"],
                        "title": rule["title"],
                        "description": rule["description"],
                        "severity": rule["severity"],
                        "event_name": event["event_name"],
                        "event_time": event["event_time"],
                        "username": event["username"],
                        "source_ip": event["source_ip"],
                        "aws_region": event["aws_region"],
                        "resources": event["resources"],
                        "error_code": event.get("error_code"),
                    })
            except Exception:
                continue

    # Stats
    severity_count = Counter(t["severity"] for t in threats)
    event_types = Counter(e["event_name"] for e in events)
    unique_ips = set(e["source_ip"] for e in events if e["source_ip"])
    unique_users = set(e["username"] for e in events if e["username"])

    return {
        "status": "completed",
        "analysis_period": f"Last {hours} hours",
        "total_events": len(events),
        "total_threats": len(threats),
        "severity_summary": {
            "critical": severity_count.get("critical", 0),
            "high": severity_count.get("high", 0),
            "medium": severity_count.get("medium", 0),
            "low": severity_count.get("low", 0),
        },
        "threats": sorted(threats, key=lambda t: ["critical", "high", "medium", "low"].index(t["severity"])),
        "activity_summary": {
            "unique_ips": list(unique_ips)[:20],
            "unique_users": list(unique_users),
            "top_events": event_types.most_common(10),
            "event_count": len(events),
        },
    }

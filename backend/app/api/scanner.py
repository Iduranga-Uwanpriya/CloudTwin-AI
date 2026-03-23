"""
Live AWS Scanner API — trigger scans, view results, get history.
"""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.db.models import User, AwsAccount, ScanResult, ComplianceFinding
from backend.app.auth import get_current_user
from backend.app.services.aws_scanner import scan_aws_account
from backend.app.compliance.engine import compliance_engine

router = APIRouter(prefix="/scanner", tags=["Live Scanner"])


# ── Schemas ──────────────────────────────────────────────────

class ScanResponse(BaseModel):
    scan_id: str
    overall_score: float
    total_checks: int
    passed_checks: int
    failed_checks: int
    resources_scanned: int
    scan_duration_seconds: float | None
    findings_summary: dict


class ScanHistoryItem(BaseModel):
    scan_id: str
    overall_score: float
    total_checks: int
    passed_checks: int
    failed_checks: int
    resources_scanned: int
    created_at: str


# ── Endpoints ────────────────────────────────────────────────

@router.post("/{account_id}/scan", response_model=ScanResponse)
def trigger_scan(
    account_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Trigger a live scan of a connected AWS account.
    Assumes the cross-account role, reads resources, runs compliance checks,
    and stores results in the database.
    """
    account = (
        db.query(AwsAccount)
        .filter(AwsAccount.id == account_id, AwsAccount.user_id == current_user.id, AwsAccount.is_active == True)
        .first()
    )
    if not account:
        raise HTTPException(status_code=404, detail="AWS account not found")

    # 1. Scan live AWS resources
    try:
        inventory = scan_aws_account(account)
    except Exception as e:
        raise HTTPException(
            status_code=502,
            detail=f"Failed to connect to AWS account. Check your IAM role and ExternalId. Error: {str(e)}",
        )

    # 2. Run compliance checks on discovered resources
    all_findings = []

    # S3 checks
    for bucket in inventory["resources"].get("s3", []):
        result = compliance_engine.scan_resource(bucket["name"], bucket)
        for check_key, check_val in result.get("checks", {}).items():
            rule = _find_rule(check_key)
            all_findings.append({
                "resource_type": "s3",
                "resource_id": bucket["name"],
                "rule_id": rule.get("rule_id", check_key),
                "rule_title": rule.get("title", check_key),
                "status": check_val.get("status", "SKIP"),
                "severity": rule.get("severity", "medium"),
                "iso_control": rule.get("iso_control"),
                "nist_control": rule.get("nist_control"),
                "remediation": rule.get("remediation"),
                "details": check_val,
            })

    # EC2 checks
    for instance in inventory["resources"].get("ec2", []):
        ec2_config = {
            "monitoring": instance.get("monitoring") == "enabled",
            "iam_profile": instance.get("iam_profile"),
            "ebs_optimized": instance.get("ebs_optimized", False),
        }
        for rule_id, title, check_key, severity in [
            ("EC2-001", "EC2 Detailed Monitoring", "monitoring", "medium"),
            ("EC2-002", "EC2 IAM Role Attached", "iam_profile", "high"),
            ("EC2-003", "EC2 EBS Optimized", "ebs_optimized", "low"),
        ]:
            val = ec2_config.get(check_key)
            status = "PASS" if val else "FAIL"
            all_findings.append({
                "resource_type": "ec2",
                "resource_id": instance["instance_id"],
                "rule_id": rule_id,
                "rule_title": title,
                "status": status,
                "severity": severity,
                "iso_control": "A.12.4.1",
                "nist_control": "SI-4",
                "remediation": f"Enable {check_key} for {instance['instance_id']}",
                "details": {"value": val},
            })

    # Security Group checks
    for sg in inventory["resources"].get("security_groups", []):
        status = "FAIL" if sg.get("open_to_world") else "PASS"
        all_findings.append({
            "resource_type": "security_group",
            "resource_id": sg["group_id"],
            "rule_id": "SG-001",
            "rule_title": "No Unrestricted Ingress (0.0.0.0/0)",
            "status": status,
            "severity": "critical",
            "iso_control": "A.13.1.1",
            "nist_control": "SC-7",
            "remediation": f"Restrict ingress rules on {sg['group_id']} to specific CIDR ranges",
            "details": {"open_rules": sg.get("open_ingress_rules", [])},
        })

    # RDS checks
    for rds in inventory["resources"].get("rds", []):
        for rule_id, title, check_key, severity in [
            ("RDS-001", "RDS Storage Encryption", "storage_encrypted", "critical"),
            ("RDS-002", "RDS Not Publicly Accessible", "publicly_accessible", "critical"),
            ("RDS-003", "RDS Multi-AZ", "multi_az", "high"),
            ("RDS-004", "RDS Backup Retention", "backup_retention", "medium"),
        ]:
            val = rds.get(check_key)
            if check_key == "publicly_accessible":
                status = "FAIL" if val else "PASS"
            elif check_key == "backup_retention":
                status = "PASS" if val and val >= 7 else "FAIL"
            else:
                status = "PASS" if val else "FAIL"

            all_findings.append({
                "resource_type": "rds",
                "resource_id": rds["db_instance_id"],
                "rule_id": rule_id,
                "rule_title": title,
                "status": status,
                "severity": severity,
                "iso_control": "A.10.1.1",
                "nist_control": "SC-28",
                "remediation": f"Fix {check_key} for {rds['db_instance_id']}",
                "details": {"value": val},
            })

    # VPC flow log checks
    for vpc in inventory["resources"].get("vpc", []):
        status = "PASS" if vpc.get("flow_logs_enabled") else "FAIL"
        all_findings.append({
            "resource_type": "vpc",
            "resource_id": vpc["vpc_id"],
            "rule_id": "VPC-001",
            "rule_title": "VPC Flow Logs Enabled",
            "status": status,
            "severity": "high",
            "iso_control": "A.12.4.1",
            "nist_control": "AU-2",
            "remediation": f"Enable flow logs for {vpc['vpc_id']}",
            "details": {"flow_logs_enabled": vpc.get("flow_logs_enabled")},
        })

    # 3. Calculate scores
    total = len(all_findings)
    passed = sum(1 for f in all_findings if f["status"] == "PASS")
    failed = total - passed
    score = round((passed / total) * 100, 2) if total > 0 else 100.0

    # 4. Persist to DB
    scan = ScanResult(
        user_id=current_user.id,
        aws_account_id=account_id,
        overall_score=score,
        total_checks=total,
        passed_checks=passed,
        failed_checks=failed,
        resources_scanned=inventory.get("total_resources", 0),
        scan_duration_seconds=inventory.get("scan_duration_seconds"),
    )
    db.add(scan)
    db.flush()

    for f in all_findings:
        finding = ComplianceFinding(
            scan_id=scan.id,
            resource_type=f["resource_type"],
            resource_id=f["resource_id"],
            rule_id=f["rule_id"],
            rule_title=f["rule_title"],
            status=f["status"],
            severity=f["severity"],
            iso_control=f.get("iso_control"),
            nist_control=f.get("nist_control"),
            remediation=f.get("remediation"),
            details=f.get("details"),
        )
        db.add(finding)

    account.last_scanned_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(scan)

    # 5. Summary by severity
    severity_summary = {}
    for f in all_findings:
        sev = f["severity"]
        if sev not in severity_summary:
            severity_summary[sev] = {"total": 0, "passed": 0, "failed": 0}
        severity_summary[sev]["total"] += 1
        if f["status"] == "PASS":
            severity_summary[sev]["passed"] += 1
        else:
            severity_summary[sev]["failed"] += 1

    return ScanResponse(
        scan_id=scan.id,
        overall_score=score,
        total_checks=total,
        passed_checks=passed,
        failed_checks=failed,
        resources_scanned=inventory.get("total_resources", 0),
        scan_duration_seconds=inventory.get("scan_duration_seconds"),
        findings_summary=severity_summary,
    )


@router.get("/{account_id}/history", response_model=list[ScanHistoryItem])
def scan_history(
    account_id: str,
    limit: int = 20,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get scan history for an AWS account."""
    account = (
        db.query(AwsAccount)
        .filter(AwsAccount.id == account_id, AwsAccount.user_id == current_user.id)
        .first()
    )
    if not account:
        raise HTTPException(status_code=404, detail="AWS account not found")

    scans = (
        db.query(ScanResult)
        .filter(ScanResult.aws_account_id == account_id)
        .order_by(ScanResult.created_at.desc())
        .limit(limit)
        .all()
    )
    return [
        ScanHistoryItem(
            scan_id=s.id,
            overall_score=s.overall_score,
            total_checks=s.total_checks,
            passed_checks=s.passed_checks,
            failed_checks=s.failed_checks,
            resources_scanned=s.resources_scanned,
            created_at=str(s.created_at),
        )
        for s in scans
    ]


@router.get("/results/{scan_id}")
def get_scan_findings(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get detailed findings for a specific scan."""
    scan = (
        db.query(ScanResult)
        .filter(ScanResult.id == scan_id, ScanResult.user_id == current_user.id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = (
        db.query(ComplianceFinding)
        .filter(ComplianceFinding.scan_id == scan_id)
        .order_by(ComplianceFinding.severity.desc(), ComplianceFinding.status)
        .all()
    )

    return {
        "scan_id": scan.id,
        "overall_score": scan.overall_score,
        "total_checks": scan.total_checks,
        "passed_checks": scan.passed_checks,
        "failed_checks": scan.failed_checks,
        "created_at": str(scan.created_at),
        "findings": [
            {
                "resource_type": f.resource_type,
                "resource_id": f.resource_id,
                "rule_id": f.rule_id,
                "rule_title": f.rule_title,
                "status": f.status,
                "severity": f.severity,
                "iso_control": f.iso_control,
                "nist_control": f.nist_control,
                "remediation": f.remediation,
                "details": f.details,
            }
            for f in findings
        ],
    }


def _find_rule(check_key: str) -> dict:
    """Look up compliance rule metadata by check_key."""
    from backend.app.compliance.rules import S3_RULES, EC2_RULES, IAM_RULES
    for rule in S3_RULES + EC2_RULES + IAM_RULES:
        if rule.check_key == check_key:
            return {
                "rule_id": rule.rule_id,
                "title": rule.title,
                "severity": rule.severity,
                "iso_control": rule.iso_control,
                "nist_control": rule.nist_control,
                "remediation": rule.remediation,
            }
    return {"rule_id": check_key, "title": check_key, "severity": "medium"}

"""
Live AWS Scanner API — trigger scans, view results, get history, generate Terraform, clone to twin.
"""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.db.models import User, AwsAccount, ScanResult, ComplianceFinding
from backend.app.auth import get_current_user
from backend.app.services.aws_scanner import scan_aws_account
from backend.app.services.tf_generator import generate_terraform
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
        result = compliance_engine.scan_resource("s3_bucket", bucket["name"], bucket)
        for check_key, check_val in result.checks.items():
            rule = _find_rule(check_key)
            all_findings.append({
                "resource_type": "s3",
                "resource_id": bucket["name"],
                "rule_id": rule.get("rule_id", check_key),
                "rule_title": rule.get("title", check_key),
                "status": check_val.status,
                "severity": rule.get("severity", check_val.severity),
                "iso_control": rule.get("iso_control"),
                "nist_control": rule.get("nist_control"),
                "remediation": rule.get("remediation", check_val.remediation),
                "details": {"message": check_val.message},
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

    # Count only resources that actually have compliance checks (exclude IAM etc.)
    actual_resources = len(set((f["resource_type"], f["resource_id"]) for f in all_findings))

    # 4. Persist to DB
    scan = ScanResult(
        user_id=current_user.id,
        aws_account_id=account_id,
        overall_score=score,
        total_checks=total,
        passed_checks=passed,
        failed_checks=failed,
        resources_scanned=actual_resources,
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
        resources_scanned=actual_resources,
        scan_duration_seconds=inventory.get("scan_duration_seconds"),
        findings_summary=severity_summary,
    )


@router.get("/{account_id}/history")
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

    results = []
    for s in scans:
        # Get distinct resources for this scan
        resources = (
            db.query(ComplianceFinding.resource_type, ComplianceFinding.resource_id)
            .filter(ComplianceFinding.scan_id == s.id)
            .distinct()
            .all()
        )
        resource_list = [{"type": r[0], "id": r[1]} for r in resources]

        results.append({
            "scan_id": s.id,
            "overall_score": s.overall_score,
            "total_checks": s.total_checks,
            "passed_checks": s.passed_checks,
            "failed_checks": s.failed_checks,
            "resources_scanned": s.resources_scanned,
            "created_at": str(s.created_at),
            "resources": resource_list,
        })

    return results


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


@router.post("/{account_id}/generate-terraform")
def generate_terraform_from_scan(
    account_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Scan a connected AWS account and generate Terraform (.tf) representing
    the current state. This is the first step of the "Clone to Digital Twin" flow.
    """
    account = (
        db.query(AwsAccount)
        .filter(AwsAccount.id == account_id, AwsAccount.user_id == current_user.id, AwsAccount.is_active == True)
        .first()
    )
    if not account:
        raise HTTPException(status_code=404, detail="AWS account not found")

    try:
        inventory = scan_aws_account(account)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to scan AWS account: {str(e)}")

    tf_content = generate_terraform(inventory)

    return {
        "status": "success",
        "account_alias": account.account_alias,
        "resources_found": inventory.get("total_resources", 0),
        "terraform": tf_content,
    }


@router.post("/{account_id}/generate-terraform/download")
def download_terraform(
    account_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Download the generated Terraform as a .tf file."""
    account = (
        db.query(AwsAccount)
        .filter(AwsAccount.id == account_id, AwsAccount.user_id == current_user.id, AwsAccount.is_active == True)
        .first()
    )
    if not account:
        raise HTTPException(status_code=404, detail="AWS account not found")

    try:
        inventory = scan_aws_account(account)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to scan AWS account: {str(e)}")

    tf_content = generate_terraform(inventory)

    return PlainTextResponse(
        content=tf_content,
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename={account.account_alias}_infrastructure.tf"},
    )


@router.post("/{account_id}/clone-to-twin")
def clone_to_digital_twin(
    account_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Full Clone-to-Twin flow:
    1. Scan real AWS account
    2. Generate Terraform
    3. Deploy S3 buckets to LocalStack digital twin
    4. Return twin status + compliance scan results
    """
    account = (
        db.query(AwsAccount)
        .filter(AwsAccount.id == account_id, AwsAccount.user_id == current_user.id, AwsAccount.is_active == True)
        .first()
    )
    if not account:
        raise HTTPException(status_code=404, detail="AWS account not found")

    # 1. Scan real AWS
    try:
        inventory = scan_aws_account(account)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to scan AWS account: {str(e)}")

    # 2. Generate Terraform
    tf_content = generate_terraform(inventory)

    # 3. Deploy S3 buckets to LocalStack
    from backend.app.services.digital_twin import get_s3_client
    from backend.app.config import settings
    s3 = get_s3_client()
    cloned_buckets = []

    for bucket in inventory["resources"].get("s3", []):
        name = bucket["name"]
        try:
            create_args = {"Bucket": name}
            if settings.AWS_REGION != "us-east-1":
                create_args["CreateBucketConfiguration"] = {"LocationConstraint": settings.AWS_REGION}
            s3.create_bucket(**create_args)
        except Exception as e:
            if "BucketAlreadyOwnedByYou" not in str(e):
                continue

        # Replicate config
        if bucket.get("encryption"):
            try:
                s3.put_bucket_encryption(
                    Bucket=name,
                    ServerSideEncryptionConfiguration={
                        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
                    },
                )
            except Exception:
                pass

        if bucket.get("versioning") == "Enabled":
            try:
                s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
            except Exception:
                pass

        pab = bucket.get("public_access_block")
        if pab:
            try:
                s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=pab)
            except Exception:
                pass

        cloned_buckets.append(name)

    # 4. Run compliance scan on cloned buckets
    scan_results = []
    for name in cloned_buckets:
        result = compliance_engine.scan_resource("s3_bucket", name, {"name": name})
        scan_results.append({"bucket": name, "score": result.compliance_score})

    return {
        "status": "success",
        "message": f"Cloned {len(cloned_buckets)} resources to digital twin",
        "cloned_resources": cloned_buckets,
        "terraform": tf_content,
        "compliance_preview": scan_results,
        "total_resources_in_account": inventory.get("total_resources", 0),
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


# ── CloudTrail Threat Analysis ────────────────────────────────

@router.post("/{account_id}/cloudtrail-threats")
def analyze_cloudtrail_threats(
    account_id: str,
    hours: int = 24,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Analyze CloudTrail events for suspicious activity.
    Pulls recent events and applies threat detection rules.
    """
    account = (
        db.query(AwsAccount)
        .filter(AwsAccount.id == account_id, AwsAccount.user_id == current_user.id, AwsAccount.is_active == True)
        .first()
    )
    if not account:
        raise HTTPException(status_code=404, detail="AWS account not found")

    from backend.app.services.aws_scanner import get_aws_session
    from backend.app.services.cloudtrail_analyzer import analyze_cloudtrail

    try:
        session = get_aws_session(account)
    except Exception as e:
        raise HTTPException(
            status_code=502,
            detail=f"Failed to connect to AWS. Check IAM role. Error: {str(e)}",
        )

    results = analyze_cloudtrail(session, hours=hours)

    if results.get("status") == "error":
        raise HTTPException(status_code=502, detail=results.get("error", "CloudTrail analysis failed"))

    return results


# ── VPC Flow Log + ML Analysis ────────────────────────────────

@router.post("/{account_id}/vpc-flowlog-analysis")
def analyze_vpc_flow_logs(
    account_id: str,
    hours: int = 1,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Pull VPC Flow Logs from CloudWatch and run them through
    the trained ML anomaly detection models (IF + SVM + Autoencoder).
    """
    account = (
        db.query(AwsAccount)
        .filter(AwsAccount.id == account_id, AwsAccount.user_id == current_user.id, AwsAccount.is_active == True)
        .first()
    )
    if not account:
        raise HTTPException(status_code=404, detail="AWS account not found")

    from backend.app.services.aws_scanner import get_aws_session
    from backend.app.services.vpc_flowlog_analyzer import pull_vpc_flow_logs

    try:
        session = get_aws_session(account)
    except Exception as e:
        raise HTTPException(
            status_code=502,
            detail=f"Failed to connect to AWS. Check IAM role. Error: {str(e)}",
        )

    results = pull_vpc_flow_logs(session, hours=hours)

    if results.get("status") == "error":
        raise HTTPException(status_code=502, detail=results.get("message", "VPC Flow Log analysis failed"))

    return results

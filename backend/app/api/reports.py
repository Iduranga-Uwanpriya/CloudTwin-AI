"""
Report Generation API Routes
Generates compliance and anomaly detection reports in HTML format
with SHA-256 signatures for tamper-proof auditing
"""
from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse
from backend.app.services.report_generator import ReportGenerator
from backend.app.services.compliance_engine import check_bucket_compliance
from backend.app.services.digital_twin import list_buckets
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent.parent.parent))
from blockchain_audit.hash_chain import blockchain_logger

router = APIRouter(prefix="/reports", tags=["Reports"])
report_gen = ReportGenerator()


@router.get("/compliance/{bucket_name}", response_class=HTMLResponse)
def compliance_report_for_bucket(bucket_name: str):
    """
    Generate an HTML compliance report for a specific S3 bucket.

    The report includes compliance scores, control references
    (ISO 27001 / NIST 800-53), and a SHA-256 tamper-proof signature.
    """
    try:
        result = check_bucket_compliance(bucket_name)
        report = report_gen.generate_compliance_report(result)
        return HTMLResponse(
            content=report["content"],
            headers={"X-Report-Signature": report["signature"],
                     "X-Report-ID": report["report_id"]},
        )
    except Exception as e:
        raise HTTPException(status_code=500,
                            detail=f"Report generation failed: {str(e)}")


@router.get("/compliance", response_class=HTMLResponse)
def compliance_report_all():
    """
    Generate an HTML compliance report for all S3 buckets
    in the LocalStack digital twin environment.
    """
    try:
        buckets = list_buckets()
        if not buckets:
            results = []
        else:
            results = [check_bucket_compliance(b) for b in buckets]

        report = report_gen.generate_compliance_report(results)
        return HTMLResponse(
            content=report["content"],
            headers={"X-Report-Signature": report["signature"],
                     "X-Report-ID": report["report_id"]},
        )
    except Exception as e:
        raise HTTPException(status_code=500,
                            detail=f"Report generation failed: {str(e)}")


@router.get("/anomaly", response_class=HTMLResponse)
def anomaly_report():
    """
    Generate an HTML anomaly detection report.

    Uses sample anomaly data (AI anomaly detection module integration
    will provide live data in the final version).
    """
    try:
        # Sample anomaly data until full AI engine integration
        sample_anomalies = [
            {
                "anomaly_type": "Unusual Access Pattern",
                "resource_name": "s3://company-data-bucket",
                "description": "Spike in GetObject requests from unknown IP range",
                "risk_level": "high",
                "confidence": "87%",
                "detected_at": "2025-03-10T14:32:00Z",
            },
            {
                "anomaly_type": "Policy Change",
                "resource_name": "s3://secure-logs-bucket",
                "description": "Bucket policy modified to allow public read access",
                "risk_level": "critical",
                "confidence": "95%",
                "detected_at": "2025-03-10T15:01:00Z",
            },
            {
                "anomaly_type": "Encryption Downgrade",
                "resource_name": "s3://financial-records",
                "description": "Server-side encryption configuration was removed",
                "risk_level": "critical",
                "confidence": "99%",
                "detected_at": "2025-03-10T15:45:00Z",
            },
            {
                "anomaly_type": "Data Exfiltration Risk",
                "resource_name": "s3://customer-pii-bucket",
                "description": "Large volume download detected outside business hours",
                "risk_level": "medium",
                "confidence": "72%",
                "detected_at": "2025-03-10T02:15:00Z",
            },
        ]

        report = report_gen.generate_anomaly_report(sample_anomalies)
        return HTMLResponse(
            content=report["content"],
            headers={"X-Report-Signature": report["signature"],
                     "X-Report-ID": report["report_id"]},
        )
    except Exception as e:
        raise HTTPException(status_code=500,
                            detail=f"Report generation failed: {str(e)}")


@router.get("/full", response_class=HTMLResponse)
def full_report():
    """
    Generate a comprehensive HTML report combining compliance results,
    anomaly detection, and blockchain audit trail integrity status.
    """
    try:
        # Compliance data
        buckets = list_buckets()
        compliance_results = [check_bucket_compliance(b) for b in buckets] if buckets else []

        # Anomaly data (sample until AI engine integration)
        anomaly_results = [
            {
                "anomaly_type": "Unusual Access Pattern",
                "resource_name": "s3://company-data-bucket",
                "description": "Spike in GetObject requests from unknown IP range",
                "risk_level": "high",
                "confidence": "87%",
                "detected_at": "2025-03-10T14:32:00Z",
            },
            {
                "anomaly_type": "Policy Change",
                "resource_name": "s3://secure-logs-bucket",
                "description": "Bucket policy modified to allow public read access",
                "risk_level": "critical",
                "confidence": "95%",
                "detected_at": "2025-03-10T15:01:00Z",
            },
        ]

        # Audit trail
        try:
            audit_trail = {
                "chain_valid": blockchain_logger.verify_chain(),
                "total_blocks": len(blockchain_logger.chain),
            }
        except Exception:
            audit_trail = {"chain_valid": False, "total_blocks": 0}

        report = report_gen.generate_full_report(
            compliance_results, anomaly_results, audit_trail,
        )
        return HTMLResponse(
            content=report["content"],
            headers={"X-Report-Signature": report["signature"],
                     "X-Report-ID": report["report_id"]},
        )
    except Exception as e:
        raise HTTPException(status_code=500,
                            detail=f"Report generation failed: {str(e)}")

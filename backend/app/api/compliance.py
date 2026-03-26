"""
Compliance API Routes
Handles compliance checking for resources
Blockchain audit trail access
"""
from fastapi import APIRouter, HTTPException
from backend.app.models.schemas import ComplianceResult
from backend.app.services.compliance_engine import check_bucket_compliance
from backend.app.services.digital_twin import list_buckets
import sys
from pathlib import Path


sys.path.append(str(Path(__file__).parent.parent.parent.parent))
from blockchain_audit.hash_chain import blockchain_logger

router = APIRouter(prefix="/compliance", tags=["Compliance"])

@router.get("/{bucket_name}", response_model=ComplianceResult)
def check_compliance(bucket_name: str):
    """
    Check compliance for a specific S3 bucket
    
    - Runs security checks
    - Calculates compliance score
    - Provides recommendations
    """
    try:
        result = check_bucket_compliance(bucket_name)
        blockchain_logger.add_compliance_log(
            resource_name=bucket_name,
            resource_type="s3_bucket",
            compliance_score=result.compliance_score,
            checks_passed=sum(1 for c in result.checks.values() if c.status == "PASS"),
            checks_total=len(result.checks),
            check_details={k: v.dict() for k, v in result.checks.items()}
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Compliance check failed: {str(e)}")

@router.get("/")
def check_all_buckets():
    """
    Check compliance for all buckets in LocalStack
    
    Returns compliance results for all resources
    """
    try:
        buckets = list_buckets()
        
        if not buckets:
            return {
                "message": "No buckets found in LocalStack",
                "total_buckets": 0,
                "results": []
            }
        
        results = []
        total_score = 0
        
        for bucket_name in buckets:
            compliance = check_bucket_compliance(bucket_name)
            results.append(compliance)
            total_score += compliance.compliance_score

            try:
                checks_passed = sum(1 for c in compliance.checks.values() if c.status == "PASS")
                blockchain_logger.add_compliance_log(
                    resource_name=bucket_name,
                    resource_type="s3_bucket",
                    compliance_score=compliance.compliance_score,
                    checks_passed=checks_passed,
                    checks_total=len(compliance.checks),
                    check_details={k: v.dict() for k, v in compliance.checks.items()}
                )
            except Exception as e:
                print(f"Warning: Failed to log to blockchain: {e}")
        avg_score = total_score / len(buckets) if buckets else 0
        
        return {
            "total_buckets": len(buckets),
            "average_compliance_score": round(avg_score, 2),
            "results": results
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
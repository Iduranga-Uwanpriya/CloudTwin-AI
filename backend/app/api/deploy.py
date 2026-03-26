"""
Deployment API Routes
Handles Terraform file upload and digital twin infrastructure management
"""
from fastapi import APIRouter, UploadFile, File, HTTPException
from backend.app.models.schemas import DeployResult
from backend.app.services.terraform_parser import parse_terraform_file, extract_s3_buckets, get_bucket_names
from backend.app.services.digital_twin import deploy_bucket, list_buckets, test_localstack_connection, get_s3_client
from backend.app.config import settings

router = APIRouter(prefix="/deploy", tags=["Deployment"])


@router.post("/infrastructure")
async def deploy_infrastructure():
    """
    Deploy the pre-configured digital twin environment to LocalStack.
    Creates compliant and non-compliant S3 buckets for testing.
    """
    try:
        s3 = get_s3_client()

        twin_buckets = [
            {"name": "secure-data-bucket", "compliant": True},
            {"name": "public-website-bucket", "compliant": False},
            {"name": "logs-archive-bucket", "compliant": True},
            {"name": "dev-test-bucket", "compliant": False},
            {"name": "backup-vault-bucket", "compliant": True},
        ]

        deployed = []
        for b in twin_buckets:
            name = b["name"]
            try:
                create_args = {"Bucket": name}
                if settings.AWS_REGION != "us-east-1":
                    create_args["CreateBucketConfiguration"] = {"LocationConstraint": settings.AWS_REGION}
                s3.create_bucket(**create_args)
            except Exception as e:
                if "BucketAlreadyOwnedByYou" not in str(e):
                    continue

            if b["compliant"]:
                try:
                    s3.put_bucket_encryption(
                        Bucket=name,
                        ServerSideEncryptionConfiguration={
                            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
                        },
                    )
                    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
                    s3.put_public_access_block(
                        Bucket=name,
                        PublicAccessBlockConfiguration={
                            "BlockPublicAcls": True,
                            "IgnorePublicAcls": True,
                            "BlockPublicPolicy": True,
                            "RestrictPublicBuckets": True,
                        },
                    )
                except Exception:
                    pass

            deployed.append(name)

        return {
            "status": "success",
            "message": f"Digital twin deployed — {len(deployed)} resources created",
            "deployed_resources": deployed,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Deployment failed: {str(e)}")


@router.post("/destroy")
async def destroy_infrastructure():
    """Delete all S3 buckets from the LocalStack digital twin."""
    try:
        s3 = get_s3_client()
        buckets = list_buckets()
        destroyed = []

        for name in buckets:
            try:
                # Empty bucket first
                objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
                for obj in objs:
                    s3.delete_object(Bucket=name, Key=obj["Key"])
                s3.delete_bucket(Bucket=name)
                destroyed.append(name)
            except Exception:
                pass

        return {
            "status": "success",
            "message": f"Destroyed {len(destroyed)} resources",
            "destroyed_resources": destroyed,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Destroy failed: {str(e)}")


@router.get("/status")
async def deploy_status():
    """Check the current state of the digital twin environment."""
    try:
        connected = test_localstack_connection()
        buckets = list_buckets() if connected else []

        return {
            "localstack_connected": connected,
            "deployed": len(buckets) > 0,
            "resources": buckets,
            "resource_count": len(buckets),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/terraform")
async def deploy_terraform(file: UploadFile = File(...)):
    """
    Upload Terraform file, deploy to LocalStack digital twin, and run compliance scan.
    """
    from backend.app.compliance.engine import compliance_engine

    temp_file_path = "temp.tf"

    try:
        content = await file.read()
        with open(temp_file_path, "wb") as f:
            f.write(content)

        tf_config = parse_terraform_file(temp_file_path)
        s3_buckets = extract_s3_buckets(tf_config)

        if not s3_buckets:
            return {
                "status": "failed",
                "deployed_resources": [],
                "message": "No S3 buckets found in Terraform file",
                "results": [],
            }

        bucket_names = get_bucket_names(s3_buckets)
        deployed = []
        for bucket_name in bucket_names:
            if deploy_bucket(bucket_name):
                deployed.append(bucket_name)

        # Run compliance scan on deployed buckets
        results = []
        for name in deployed:
            result = compliance_engine.scan_resource("s3_bucket", name, {"name": name})
            checks_dict = {}
            for check_key, check_val in result.checks.items():
                checks_dict[check_key] = {
                    "status": check_val.status,
                    "message": check_val.message,
                    "severity": check_val.severity,
                    "remediation": check_val.remediation,
                }
            results.append({
                "resource_name": name,
                "compliance_score": result.compliance_score,
                "summary": f"{sum(1 for c in result.checks.values() if c.status == 'PASS')}/{len(result.checks)} checks passed",
                "checks": checks_dict,
                "recommendations": result.recommendations,
            })

        total_score = sum(r["compliance_score"] for r in results) / len(results) if results else 0

        return {
            "status": "success",
            "deployed_resources": deployed,
            "message": f"Deployed {len(deployed)} bucket(s) — {total_score:.0f}% average compliance",
            "results": results,
        }

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Deployment failed: {str(e)}")
"""
Deployment API Routes
Handles Terraform file upload and infrastructure deployment
"""
from fastapi import APIRouter, UploadFile, File, HTTPException
from backend.app.models.schemas import DeployResult
from backend.app.services.terraform_parser import parse_terraform_file, extract_s3_buckets, get_bucket_names
from backend.app.services.digital_twin import deploy_bucket

router = APIRouter(prefix="/deploy", tags=["Deployment"])

@router.post("/", response_model=DeployResult)
async def deploy_terraform(file: UploadFile = File(...)):
    """
    Upload Terraform file and deploy to LocalStack digital twin
    
    - Parses .tf file
    - Extracts S3 bucket configurations
    - Deploys to LocalStack
    - Returns deployment results
    """
    # Save uploaded file temporarily
    temp_file_path = "temp.tf"
    
    try:
        content = await file.read()
        with open(temp_file_path, "wb") as f:
            f.write(content)
        
        # Parse Terraform file
        tf_config = parse_terraform_file(temp_file_path)
        
        # Extract S3 buckets
        s3_buckets = extract_s3_buckets(tf_config)
        
        if not s3_buckets:
            return DeployResult(
                status="failed",
                deployed_resources=[],
                message="No S3 buckets found in Terraform file"
            )
        
        # Get bucket names
        bucket_names = get_bucket_names(s3_buckets)
        
        # Deploy each bucket
        deployed = []
        for bucket_name in bucket_names:
            success = deploy_bucket(bucket_name)
            if success:
                deployed.append(bucket_name)
        
        return DeployResult(
            status="success",
            deployed_resources=deployed,
            message=f"Successfully deployed {len(deployed)} bucket(s)"
        )
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Deployment failed: {str(e)}")
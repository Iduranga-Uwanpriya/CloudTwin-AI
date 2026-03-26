"""
Digital Twin Service
Manages LocalStack connection and AWS resource simulation
"""
import boto3
from backend.app.config import settings

def get_s3_client():
    """
    Create S3 client configured for LocalStack
    
    Returns:
        boto3.client: Configured S3 client
    """
    return boto3.client(
        's3',
        endpoint_url=settings.LOCALSTACK_ENDPOINT,
        aws_access_key_id=settings.AWS_ACCESS_KEY,
        aws_secret_access_key=settings.AWS_SECRET_KEY,
        region_name=settings.AWS_REGION
    )

def deploy_bucket(bucket_name: str) -> bool:
    """
    Deploy S3 bucket to LocalStack digital twin
    
    Args:
        bucket_name: Name of bucket to create
        
    Returns:
        bool: True if successful
    """
    try:
        s3_client = get_s3_client()
        create_args = {"Bucket": bucket_name}
        if settings.AWS_REGION != "us-east-1":
            create_args["CreateBucketConfiguration"] = {"LocationConstraint": settings.AWS_REGION}
        s3_client.create_bucket(**create_args)
        return True
    except Exception as e:
        if 'BucketAlreadyOwnedByYou' in str(e):
            return True  # Already exists
        print(f"Error deploying bucket {bucket_name}: {e}")
        return False

def list_buckets() -> list:
    """
    List all buckets in LocalStack
    
    Returns:
        list: Bucket names
    """
    try:
        s3_client = get_s3_client()
        response = s3_client.list_buckets()
        return [bucket['Name'] for bucket in response.get('Buckets', [])]
    except Exception as e:
        print(f"Error listing buckets: {e}")
        return []

def test_localstack_connection() -> bool:
    """
    Test LocalStack connectivity
    
    Returns:
        bool: True if connected
    """
    try:
        s3_client = get_s3_client()
        s3_client.list_buckets()
        return True
    except Exception:
        return False
"""
Terraform File Parser Service
Parses .tf files and extracts infrastructure configuration
"""
import hcl2
from typing import Dict, List

def parse_terraform_file(file_path: str) -> Dict:
    try:
        with open(file_path, 'r') as f:
            data = hcl2.load(f)

        if not data:
            return {}

        return data
    except Exception as e:
        print("Terraform parse error:", e)
        return {}
def extract_s3_buckets(tf_config: Dict) -> Dict:
    resources = tf_config.get('resource')

    if not resources:
        return {}

    # Case 1: resource is a list
    if isinstance(resources, list):
        for block in resources:
            if isinstance(block, dict) and 'aws_s3_bucket' in block:
                return block['aws_s3_bucket']

    # Case 2: resource is a dict
    if isinstance(resources, dict):
        return resources.get('aws_s3_bucket', {})

    return {}

def get_bucket_names(s3_buckets: Dict) -> List[str]:
    """
    Extract bucket names from S3 configurations
    
    Args:
        s3_buckets: S3 bucket configurations
        
    Returns:
        List[str]: List of bucket names
    """
    bucket_names = []
    for bucket_key, bucket_config in s3_buckets.items():
        bucket_name = bucket_config.get('bucket', bucket_key)
        bucket_names.append(bucket_name)
    return bucket_names
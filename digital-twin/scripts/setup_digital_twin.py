"""
CloudTwin AI - Digital Twin Setup Script
Uses boto3 to configure LocalStack with sample compliant and
non-compliant AWS resources for testing and demonstration.
Can be run independently of the main application.
"""
import boto3
import json
import time
from datetime import datetime, timezone

#  CONFIGURATION 

LOCALSTACK_ENDPOINT = "http://localhost:4566"
AWS_REGION = "us-east-1"
AWS_ACCESS_KEY = "test"
AWS_SECRET_KEY = "test"


def get_client(service: str):
    """Create a boto3 client configured for LocalStack."""
    return boto3.client(
        service,
        endpoint_url=LOCALSTACK_ENDPOINT,
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY,
        region_name=AWS_REGION,
    )


#  S3 BUCKET SETUP 

def create_compliant_bucket(s3, bucket_name: str):
    """Create a fully compliant S3 bucket with encryption, versioning, and access blocks."""
    print(f"  Creating compliant bucket: {bucket_name}")
    try:
        s3.create_bucket(Bucket=bucket_name)
    except s3.exceptions.BucketAlreadyOwnedByYou:
        pass

    # Enable encryption
    s3.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            "Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
            ]
        },
    )

    # Enable versioning
    s3.put_bucket_versioning(
        Bucket=bucket_name,
        VersioningConfiguration={"Status": "Enabled"},
    )

    # Block public access
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    # Enforce HTTPS-only policy
    s3.put_bucket_policy(
        Bucket=bucket_name,
        Policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyUnencryptedTransport",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": [
                        f"arn:aws:s3:::{bucket_name}",
                        f"arn:aws:s3:::{bucket_name}/*",
                    ],
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                }
            ],
        }),
    )
    print(f"    [COMPLIANT] Encryption, versioning, access block, HTTPS policy")


def create_noncompliant_bucket(s3, bucket_name: str):
    """Create a non-compliant S3 bucket with no security controls."""
    print(f"  Creating non-compliant bucket: {bucket_name}")
    try:
        s3.create_bucket(Bucket=bucket_name)
    except s3.exceptions.BucketAlreadyOwnedByYou:
        pass
    print(f"    [NON-COMPLIANT] No encryption, no versioning, no access block")


def create_partial_bucket(s3, bucket_name: str):
    """Create a partially compliant S3 bucket (encryption only)."""
    print(f"  Creating partially compliant bucket: {bucket_name}")
    try:
        s3.create_bucket(Bucket=bucket_name)
    except s3.exceptions.BucketAlreadyOwnedByYou:
        pass

    s3.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            "Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
            ]
        },
    )
    print(f"    [PARTIAL] Encryption only")


def setup_s3_buckets():
    """Create a mix of compliant and non-compliant S3 buckets."""
    print("\n[1/4] Setting up S3 buckets...")
    s3 = get_client("s3")

    create_compliant_bucket(s3, "secure-data-bucket")
    create_compliant_bucket(s3, "secure-audit-logs")
    create_noncompliant_bucket(s3, "public-website-bucket")
    create_noncompliant_bucket(s3, "temp-upload-bucket")
    create_partial_bucket(s3, "partial-logs-bucket")

    # Upload sample objects
    print("  Uploading sample objects...")
    s3.put_object(
        Bucket="secure-data-bucket",
        Key="config/settings.json",
        Body=json.dumps({"app": "CloudTwin AI", "version": "1.0.0"}),
    )
    s3.put_object(
        Bucket="public-website-bucket",
        Key="index.html",
        Body="<html><body>Sample website</body></html>",
    )
    print("    [+] Sample objects uploaded")


#  CLOUDTRAIL SETUP 

def setup_cloudtrail():
    """Configure CloudTrail for audit logging."""
    print("\n[2/4] Setting up CloudTrail...")
    s3 = get_client("s3")
    ct = get_client("cloudtrail")

    # Create trail destination bucket
    try:
        s3.create_bucket(Bucket="cloudtwin-cloudtrail-logs")
    except Exception:
        pass

    try:
        ct.create_trail(
            Name="cloudtwin-audit-trail",
            S3BucketName="cloudtwin-cloudtrail-logs",
            IsMultiRegionTrail=True,
            EnableLogFileValidation=True,
        )
        ct.start_logging(Name="cloudtwin-audit-trail")
        print("  [+] CloudTrail trail created and logging started")
    except Exception as e:
        print(f"  [!] CloudTrail setup: {e}")


#  VPC / SECURITY GROUP SETUP 

def setup_vpc_and_security_groups():
    """Create VPC with compliant and non-compliant security groups."""
    print("\n[3/4] Setting up VPC and security groups...")
    ec2 = get_client("ec2")

    # Create VPC
    try:
        vpc_resp = ec2.create_vpc(
            CidrBlock="10.0.0.0/16",
            TagSpecifications=[
                {
                    "ResourceType": "vpc",
                    "Tags": [{"Key": "Name", "Value": "cloudtwin-vpc"}],
                }
            ],
        )
        vpc_id = vpc_resp["Vpc"]["VpcId"]
        print(f"  [+] VPC created: {vpc_id}")
    except Exception as e:
        print(f"  [!] VPC creation: {e}")
        vpc_id = None
        return

    # Compliant security group
    try:
        sg_resp = ec2.create_security_group(
            GroupName="cloudtwin-sg-compliant",
            Description="Compliant SG - restricted access",
            VpcId=vpc_id,
        )
        sg_id = sg_resp["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "10.0.0.0/16", "Description": "Internal HTTPS"}],
                }
            ],
        )
        print(f"  [+] Compliant security group: {sg_id}")
    except Exception as e:
        print(f"  [!] Compliant SG: {e}")

    # Non-compliant security group
    try:
        sg_resp = ec2.create_security_group(
            GroupName="cloudtwin-sg-open",
            Description="Non-compliant SG - open to world",
            VpcId=vpc_id,
        )
        sg_id = sg_resp["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "SSH open to world"}],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3389,
                    "ToPort": 3389,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "RDP open to world"}],
                },
            ],
        )
        print(f"  [+] Non-compliant security group: {sg_id}")
    except Exception as e:
        print(f"  [!] Non-compliant SG: {e}")


#  SAMPLE CLOUDTRAIL EVENTS 

def generate_sample_cloudtrail_events():
    """Generate sample CloudTrail-style events for testing."""
    print("\n[4/4] Generating sample CloudTrail events...")

    events = [
        {
            "eventVersion": "1.08",
            "eventSource": "s3.amazonaws.com",
            "eventName": "PutBucketEncryption",
            "eventTime": datetime.now(timezone.utc).isoformat(),
            "sourceIPAddress": "10.0.1.50",
            "userAgent": "cloudtwin-setup",
            "requestParameters": {"bucketName": "secure-data-bucket"},
            "responseElements": None,
            "eventType": "AwsApiCall",
        },
        {
            "eventVersion": "1.08",
            "eventSource": "s3.amazonaws.com",
            "eventName": "DeleteBucketEncryption",
            "eventTime": datetime.now(timezone.utc).isoformat(),
            "sourceIPAddress": "203.0.113.50",
            "userAgent": "aws-cli/2.0",
            "requestParameters": {"bucketName": "public-website-bucket"},
            "responseElements": None,
            "eventType": "AwsApiCall",
        },
        {
            "eventVersion": "1.08",
            "eventSource": "ec2.amazonaws.com",
            "eventName": "AuthorizeSecurityGroupIngress",
            "eventTime": datetime.now(timezone.utc).isoformat(),
            "sourceIPAddress": "203.0.113.100",
            "userAgent": "aws-cli/2.0",
            "requestParameters": {
                "groupId": "sg-noncompliant",
                "ipPermissions": {"items": [{"ipProtocol": "tcp", "fromPort": 22, "toPort": 22}]},
            },
            "responseElements": {"_return": True},
            "eventType": "AwsApiCall",
        },
        {
            "eventVersion": "1.08",
            "eventSource": "s3.amazonaws.com",
            "eventName": "GetObject",
            "eventTime": datetime.now(timezone.utc).isoformat(),
            "sourceIPAddress": "198.51.100.25",
            "userAgent": "python-requests/2.28",
            "requestParameters": {
                "bucketName": "secure-data-bucket",
                "key": "config/settings.json",
            },
            "responseElements": None,
            "eventType": "AwsApiCall",
        },
    ]

    # Store events in the trail bucket
    s3 = get_client("s3")
    for i, event in enumerate(events):
        try:
            s3.put_object(
                Bucket="cloudtwin-cloudtrail-logs",
                Key=f"AWSLogs/sample-events/event-{i:04d}.json",
                Body=json.dumps(event, indent=2),
            )
        except Exception as e:
            print(f"  [!] Failed to store event {i}: {e}")

    print(f"  [+] {len(events)} sample CloudTrail events generated")


#  MAIN 

def main():
    print("=" * 50)
    print(" CloudTwin AI - Digital Twin Setup")
    print("=" * 50)
    print(f"Endpoint: {LOCALSTACK_ENDPOINT}")
    print(f"Region:   {AWS_REGION}")

    setup_s3_buckets()
    setup_cloudtrail()
    setup_vpc_and_security_groups()
    generate_sample_cloudtrail_events()

    print("\n" + "=" * 50)
    print(" Setup complete!")
    print(" Resources created:")
    print("   - 5 S3 buckets (2 compliant, 2 non-compliant, 1 partial)")
    print("   - 1 CloudTrail trail with sample events")
    print("   - 1 VPC with 2 security groups")
    print("=" * 50)


if __name__ == "__main__":
    main()

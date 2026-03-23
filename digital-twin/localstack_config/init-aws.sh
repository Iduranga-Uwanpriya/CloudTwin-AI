#!/bin/bash
# ============================================================
# CloudTwin AI - LocalStack Initialization Script
# Creates sample AWS resources (compliant and non-compliant)
# for the digital twin environment.
# This script runs automatically on LocalStack startup.
# ============================================================

set -e

ENDPOINT="http://localhost:4566"
REGION="us-east-1"

echo "======================================"
echo " CloudTwin AI - LocalStack Init"
echo "======================================"

# ----------------------------------------------------------
# 1. S3 Buckets
# ----------------------------------------------------------

echo "[*] Creating S3 buckets..."

# Compliant bucket - encryption + versioning + public access block
awslocal s3 mb s3://secure-data-bucket --region $REGION 2>/dev/null || true

awslocal s3api put-bucket-encryption \
    --bucket secure-data-bucket \
    --server-side-encryption-configuration '{
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
    }' --region $REGION

awslocal s3api put-bucket-versioning \
    --bucket secure-data-bucket \
    --versioning-configuration Status=Enabled \
    --region $REGION

awslocal s3api put-public-access-block \
    --bucket secure-data-bucket \
    --public-access-block-configuration '{
        "BlockPublicAcls": true,
        "IgnorePublicAcls": true,
        "BlockPublicPolicy": true,
        "RestrictPublicBuckets": true
    }' --region $REGION

echo "  [+] secure-data-bucket created (COMPLIANT)"

# Non-compliant bucket - no encryption, no versioning
awslocal s3 mb s3://public-website-bucket --region $REGION 2>/dev/null || true
echo "  [+] public-website-bucket created (NON-COMPLIANT)"

# Partially compliant bucket - encryption only
awslocal s3 mb s3://partial-logs-bucket --region $REGION 2>/dev/null || true

awslocal s3api put-bucket-encryption \
    --bucket partial-logs-bucket \
    --server-side-encryption-configuration '{
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
    }' --region $REGION

echo "  [+] partial-logs-bucket created (PARTIAL)"

# Another compliant bucket
awslocal s3 mb s3://secure-audit-logs --region $REGION 2>/dev/null || true

awslocal s3api put-bucket-encryption \
    --bucket secure-audit-logs \
    --server-side-encryption-configuration '{
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]
    }' --region $REGION

awslocal s3api put-bucket-versioning \
    --bucket secure-audit-logs \
    --versioning-configuration Status=Enabled \
    --region $REGION

awslocal s3api put-public-access-block \
    --bucket secure-audit-logs \
    --public-access-block-configuration '{
        "BlockPublicAcls": true,
        "IgnorePublicAcls": true,
        "BlockPublicPolicy": true,
        "RestrictPublicBuckets": true
    }' --region $REGION

echo "  [+] secure-audit-logs created (COMPLIANT)"

# ----------------------------------------------------------
# 2. Bucket Policies
# ----------------------------------------------------------

echo "[*] Setting bucket policies..."

awslocal s3api put-bucket-policy \
    --bucket secure-data-bucket \
    --policy '{
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DenyUnencryptedTransport",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [
                "arn:aws:s3:::secure-data-bucket",
                "arn:aws:s3:::secure-data-bucket/*"
            ],
            "Condition": {
                "Bool": {"aws:SecureTransport": "false"}
            }
        }]
    }' --region $REGION

echo "  [+] Deny-unencrypted-transport policy applied to secure-data-bucket"

# ----------------------------------------------------------
# 3. CloudTrail Configuration
# ----------------------------------------------------------

echo "[*] Creating CloudTrail trail..."

# Ensure trail destination bucket exists
awslocal s3 mb s3://cloudtwin-cloudtrail-logs --region $REGION 2>/dev/null || true

awslocal cloudtrail create-trail \
    --name cloudtwin-audit-trail \
    --s3-bucket-name cloudtwin-cloudtrail-logs \
    --is-multi-region-trail \
    --enable-log-file-validation \
    --region $REGION 2>/dev/null || true

awslocal cloudtrail start-logging \
    --name cloudtwin-audit-trail \
    --region $REGION 2>/dev/null || true

echo "  [+] CloudTrail trail created and logging started"

# ----------------------------------------------------------
# 4. VPC and Security Groups
# ----------------------------------------------------------

echo "[*] Creating VPC and security groups..."

VPC_ID=$(awslocal ec2 create-vpc \
    --cidr-block 10.0.0.0/16 \
    --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=cloudtwin-vpc}]' \
    --query 'Vpc.VpcId' --output text \
    --region $REGION 2>/dev/null) || VPC_ID="vpc-existing"

echo "  [+] VPC created: $VPC_ID"

# Compliant security group - restricted ingress
SG_COMPLIANT=$(awslocal ec2 create-security-group \
    --group-name cloudtwin-sg-compliant \
    --description "Compliant SG - restricted access" \
    --vpc-id $VPC_ID \
    --query 'GroupId' --output text \
    --region $REGION 2>/dev/null) || SG_COMPLIANT="sg-existing"

awslocal ec2 authorize-security-group-ingress \
    --group-id $SG_COMPLIANT \
    --protocol tcp --port 443 \
    --cidr 10.0.0.0/16 \
    --region $REGION 2>/dev/null || true

echo "  [+] Compliant security group created: $SG_COMPLIANT"

# Non-compliant security group - open to the world
SG_NONCOMPLIANT=$(awslocal ec2 create-security-group \
    --group-name cloudtwin-sg-open \
    --description "Non-compliant SG - open to world" \
    --vpc-id $VPC_ID \
    --query 'GroupId' --output text \
    --region $REGION 2>/dev/null) || SG_NONCOMPLIANT="sg-existing"

awslocal ec2 authorize-security-group-ingress \
    --group-id $SG_NONCOMPLIANT \
    --protocol tcp --port 22 \
    --cidr 0.0.0.0/0 \
    --region $REGION 2>/dev/null || true

awslocal ec2 authorize-security-group-ingress \
    --group-id $SG_NONCOMPLIANT \
    --protocol tcp --port 3389 \
    --cidr 0.0.0.0/0 \
    --region $REGION 2>/dev/null || true

echo "  [+] Non-compliant security group created: $SG_NONCOMPLIANT"

# ----------------------------------------------------------
# Done
# ----------------------------------------------------------

echo ""
echo "======================================"
echo " LocalStack initialization complete!"
echo " Buckets: 5 (2 compliant, 1 partial, 1 non-compliant, 1 trail)"
echo " Security Groups: 2 (1 compliant, 1 non-compliant)"
echo " CloudTrail: 1 trail active"
echo "======================================"

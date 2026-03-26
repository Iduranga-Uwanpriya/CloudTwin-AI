"""
Terraform Generator — converts scanned AWS inventory into .tf configuration.
Used for the "Clone to Digital Twin" flow:
  Scan real AWS → generate .tf → deploy to LocalStack → test fixes safely
"""


def generate_terraform(inventory: dict) -> str:
    """
    Convert a scan_aws_account() inventory dict into Terraform HCL.
    Returns a string of valid Terraform configuration.
    """
    lines = [
        '# =============================================================',
        '# CloudTwin AI — Auto-generated Terraform from live AWS scan',
        '# =============================================================',
        '',
        'terraform {',
        '  required_providers {',
        '    aws = { source = "hashicorp/aws", version = "~> 5.0" }',
        '  }',
        '}',
        '',
        'provider "aws" {',
        '  region = "us-east-1"',
        '}',
        '',
    ]

    resources = inventory.get("resources", {})

    # ── S3 Buckets ────────────────────────────────────────────
    for bucket in resources.get("s3", []):
        name = bucket["name"]
        safe = _safe_name(name)

        lines.append(f'# S3 Bucket: {name}')
        lines.append(f'resource "aws_s3_bucket" "{safe}" {{')
        lines.append(f'  bucket = "{name}"')
        lines.append('}')
        lines.append('')

        # Versioning
        versioning = bucket.get("versioning", "Disabled")
        lines.append(f'resource "aws_s3_bucket_versioning" "{safe}_versioning" {{')
        lines.append(f'  bucket = aws_s3_bucket.{safe}.id')
        lines.append('  versioning_configuration {')
        lines.append(f'    status = "{versioning if versioning in ("Enabled", "Suspended") else "Disabled"}"')
        lines.append('  }')
        lines.append('}')
        lines.append('')

        # Encryption
        if bucket.get("encryption"):
            lines.append(f'resource "aws_s3_bucket_server_side_encryption_configuration" "{safe}_sse" {{')
            lines.append(f'  bucket = aws_s3_bucket.{safe}.id')
            lines.append('  rule {')
            lines.append('    apply_server_side_encryption_by_default {')
            lines.append('      sse_algorithm = "AES256"')
            lines.append('    }')
            lines.append('  }')
            lines.append('}')
            lines.append('')

        # Public access block
        pab = bucket.get("public_access_block")
        if pab:
            lines.append(f'resource "aws_s3_bucket_public_access_block" "{safe}_pab" {{')
            lines.append(f'  bucket = aws_s3_bucket.{safe}.id')
            lines.append(f'  block_public_acls       = {_tf_bool(pab.get("BlockPublicAcls", False))}')
            lines.append(f'  ignore_public_acls      = {_tf_bool(pab.get("IgnorePublicAcls", False))}')
            lines.append(f'  block_public_policy     = {_tf_bool(pab.get("BlockPublicPolicy", False))}')
            lines.append(f'  restrict_public_buckets = {_tf_bool(pab.get("RestrictPublicBuckets", False))}')
            lines.append('}')
            lines.append('')

    # ── EC2 Instances ─────────────────────────────────────────
    for inst in resources.get("ec2", []):
        iid = inst["instance_id"]
        safe = _safe_name(iid)
        lines.append(f'# EC2 Instance: {iid}')
        lines.append(f'resource "aws_instance" "{safe}" {{')
        lines.append(f'  ami           = "ami-placeholder"  # replace with actual AMI')
        lines.append(f'  instance_type = "{inst.get("instance_type", "t3.micro")}"')
        lines.append(f'  monitoring    = {_tf_bool(inst.get("monitoring") == "enabled")}')
        lines.append(f'  ebs_optimized = {_tf_bool(inst.get("ebs_optimized", False))}')
        if inst.get("tags"):
            lines.append('  tags = {')
            for k, v in inst["tags"].items():
                lines.append(f'    "{k}" = "{v}"')
            lines.append('  }')
        lines.append('}')
        lines.append('')

    # ── Security Groups ───────────────────────────────────────
    for sg in resources.get("security_groups", []):
        gid = sg["group_id"]
        safe = _safe_name(sg.get("group_name", gid))
        lines.append(f'# Security Group: {sg.get("group_name", gid)}')
        lines.append(f'resource "aws_security_group" "{safe}" {{')
        lines.append(f'  name        = "{sg.get("group_name", gid)}"')
        lines.append(f'  description = "{sg.get("description", "")}"')
        if sg.get("vpc_id"):
            lines.append(f'  vpc_id      = "{sg["vpc_id"]}"')
        if sg.get("open_ingress_rules"):
            for rule in sg["open_ingress_rules"]:
                lines.append('  ingress {')
                lines.append(f'    from_port   = {rule.get("from_port", 0)}')
                lines.append(f'    to_port     = {rule.get("to_port", 0)}')
                lines.append(f'    protocol    = "{rule.get("protocol", "tcp")}"')
                lines.append('    cidr_blocks = ["0.0.0.0/0"]  # WARNING: open to world')
                lines.append('  }')
        lines.append('}')
        lines.append('')

    # ── VPC ────────────────────────────────────────────────────
    for vpc in resources.get("vpc", []):
        vid = vpc["vpc_id"]
        safe = _safe_name(vid)
        lines.append(f'# VPC: {vid}')
        lines.append(f'resource "aws_vpc" "{safe}" {{')
        lines.append(f'  cidr_block = "{vpc.get("cidr_block", "10.0.0.0/16")}"')
        if vpc.get("tags"):
            lines.append('  tags = {')
            for k, v in vpc["tags"].items():
                lines.append(f'    "{k}" = "{v}"')
            lines.append('  }')
        lines.append('}')
        lines.append('')

    # ── RDS ────────────────────────────────────────────────────
    for db in resources.get("rds", []):
        dbid = db["db_instance_id"]
        safe = _safe_name(dbid)
        lines.append(f'# RDS Instance: {dbid}')
        lines.append(f'resource "aws_db_instance" "{safe}" {{')
        lines.append(f'  identifier     = "{dbid}"')
        lines.append(f'  engine         = "{db.get("engine", "mysql")}"')
        lines.append(f'  engine_version = "{db.get("engine_version", "8.0")}"')
        lines.append(f'  instance_class = "{db.get("instance_class", "db.t3.micro")}"')
        lines.append(f'  allocated_storage = 20')
        lines.append(f'  storage_encrypted    = {_tf_bool(db.get("storage_encrypted", False))}')
        lines.append(f'  publicly_accessible  = {_tf_bool(db.get("publicly_accessible", False))}')
        lines.append(f'  multi_az             = {_tf_bool(db.get("multi_az", False))}')
        lines.append(f'  backup_retention_period = {db.get("backup_retention", 0)}')
        lines.append(f'  skip_final_snapshot  = true')
        lines.append('}')
        lines.append('')

    return '\n'.join(lines)


def _safe_name(name: str) -> str:
    """Convert a resource name/ID to a valid Terraform resource name."""
    return name.replace("-", "_").replace(".", "_").replace("/", "_").lower()


def _tf_bool(val) -> str:
    """Convert Python bool to Terraform bool string."""
    return "true" if val else "false"

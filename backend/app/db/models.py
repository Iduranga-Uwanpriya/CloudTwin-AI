"""
SQLAlchemy ORM models for CloudTwin AI.
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Float, Boolean, Integer, DateTime, Text, JSON,
    ForeignKey, Enum as SAEnum,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


def _utcnow():
    return datetime.now(timezone.utc)


def _uuid():
    return str(uuid.uuid4())


# ─────────────────────────── Users ───────────────────────────

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=_uuid)
    email = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, nullable=True)
    company = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow)

    # Relationships
    aws_accounts = relationship("AwsAccount", back_populates="owner", cascade="all, delete-orphan")
    scan_results = relationship("ScanResult", back_populates="user", cascade="all, delete-orphan")


# ─────────────────────────── AWS Accounts ───────────────────────────

class AwsAccount(Base):
    __tablename__ = "aws_accounts"

    id = Column(String, primary_key=True, default=_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    account_alias = Column(String, nullable=False)
    role_arn = Column(String, nullable=False)
    external_id = Column(String, nullable=False, default=_uuid)
    aws_account_id = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    last_scanned_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow)

    # Relationships
    owner = relationship("User", back_populates="aws_accounts")
    scans = relationship("ScanResult", back_populates="aws_account", cascade="all, delete-orphan")


# ─────────────────────────── Scan Results ───────────────────────────

class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(String, primary_key=True, default=_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    aws_account_id = Column(String, ForeignKey("aws_accounts.id"), nullable=False)
    overall_score = Column(Float, nullable=False)
    total_checks = Column(Integer, default=0)
    passed_checks = Column(Integer, default=0)
    failed_checks = Column(Integer, default=0)
    resources_scanned = Column(Integer, default=0)
    scan_duration_seconds = Column(Float, nullable=True)
    status = Column(String, default="completed")  # running, completed, failed
    created_at = Column(DateTime(timezone=True), default=_utcnow)

    # Relationships
    user = relationship("User", back_populates="scan_results")
    aws_account = relationship("AwsAccount", back_populates="scans")
    findings = relationship("ComplianceFinding", back_populates="scan", cascade="all, delete-orphan")


# ─────────────────────────── Compliance Findings ───────────────────────────

class ComplianceFinding(Base):
    __tablename__ = "compliance_findings"

    id = Column(String, primary_key=True, default=_uuid)
    scan_id = Column(String, ForeignKey("scan_results.id"), nullable=False)
    resource_type = Column(String, nullable=False)       # s3, ec2, iam, sg, vpc, rds
    resource_id = Column(String, nullable=False)          # bucket name, instance id, etc.
    rule_id = Column(String, nullable=False)              # S3-001, EC2-001, etc.
    rule_title = Column(String, nullable=False)
    status = Column(String, nullable=False)               # PASS, FAIL, SKIP
    severity = Column(String, nullable=False)             # critical, high, medium, low
    iso_control = Column(String, nullable=True)
    nist_control = Column(String, nullable=True)
    remediation = Column(Text, nullable=True)
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow)

    # Relationships
    scan = relationship("ScanResult", back_populates="findings")

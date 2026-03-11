"""
Pydantic Data Models
Defines structure of all data in the API
"""
from pydantic import BaseModel, Field
from typing import Dict, List, Optional
from datetime import datetime

# ==================== COMPLIANCE MODELS ====================

class ComplianceCheck(BaseModel):
    """Single compliance check result"""
    status: str = Field(..., description="PASS or FAIL")
    message: str = Field(..., description="Explanation of the check")
    severity: str = Field(..., description="critical, high, medium, or low")
    remediation: Optional[str] = Field(None, description="How to fix if failed")

class ComplianceResult(BaseModel):
    """Complete compliance assessment for a resource"""
    resource_name: str = Field(..., description="Name of checked resource")
    resource_type: str = Field(default="s3_bucket")
    compliance_score: float = Field(..., ge=0, le=100, description="Score 0-100")
    checks: Dict[str, ComplianceCheck] = Field(..., description="Individual checks")
    summary: str = Field(..., description="Quick summary")
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    recommendations: List[str] = Field(default_factory=list)

# ==================== DEPLOYMENT MODELS ====================

class DeployResult(BaseModel):
    """Infrastructure deployment result"""
    status: str = Field(..., description="success or failed")
    deployed_resources: List[str] = Field(default_factory=list)
    message: str
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())

# ==================== BLOCKCHAIN MODELS ====================

class BlockchainBlock(BaseModel):
    """Single block in audit blockchain"""
    id: int
    timestamp: str
    resource_name: str
    compliance_score: float
    checks_passed: int
    checks_total: int
    previous_hash: str
    current_hash: str
    check_details: Dict = {}

class AuditTrailResponse(BaseModel):
    """Blockchain audit trail"""
    total_blocks: int
    chain_valid: bool
    blocks: List[BlockchainBlock]
    message: Optional[str] = None

# ==================== HEALTH CHECK ====================

class HealthCheck(BaseModel):
    """System health status"""
    status: str
    service: str
    version: str
    localstack_connected: bool
    blockchain_valid: bool
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())

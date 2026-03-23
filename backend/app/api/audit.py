"""
Audit API Routes
Handles blockchain audit trail access
"""
from fastapi import APIRouter, HTTPException, Query
from typing import Optional
import sys
from pathlib import Path

# Add parent directory to path for blockchain import
sys.path.append(str(Path(__file__).parent.parent.parent.parent))
from blockchain_audit.hash_chain import blockchain_logger

router = APIRouter(prefix="/audit", tags=["Audit"])

@router.get("/blockchain")
def get_blockchain_audit(
    resource_name: Optional[str] = Query(None, description="Filter by resource name"),
    limit: Optional[int] = Query(None, description="Limit number of results")
):
    """
    Retrieve blockchain audit trail
    
    Query Parameters:
    - resource_name: Optional filter by resource
    - limit: Optional limit number of results
    
    Returns all compliance checks logged in the blockchain
    """
    try:
        # Pass parameters correctly
        chain = blockchain_logger.get_audit_trail(
            resource_name=resource_name,
            limit=limit
        )
        is_valid, error_msg = blockchain_logger.verify_chain_integrity()
        
        # Filter out genesis block
        audit_blocks = [block for block in chain if block.get("id", 0) > 0]
        
        return {
            "total_blocks": len(audit_blocks),
            "chain_valid": is_valid,
            "blocks": audit_blocks,
            "message": "Blockchain audit trail retrieved successfully" if is_valid else f"Warning: {error_msg}"
        }
    except Exception as e:
        print(f"Error in get_blockchain_audit: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve audit trail: {str(e)}")

@router.get("/verify")
def verify_blockchain_integrity():
    """
    Verify blockchain integrity
    
    Checks if audit trail has been tampered with
    """
    try:
        is_valid, error_msg = blockchain_logger.verify_chain_integrity()
        stats = blockchain_logger.get_chain_stats()
        
        return {
            "status": "valid" if is_valid else "invalid",
            "message": "✅ Blockchain integrity verified - No tampering detected" if is_valid else f"❌ Tampering detected: {error_msg}",
            "chain_valid": is_valid,
            "statistics": stats
        }
    except Exception as e:
        print(f"Error in verify_blockchain_integrity: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/stats")
def get_blockchain_stats():
    """
    Get blockchain statistics
    
    Returns overview of audit trail
    """
    try:
        stats = blockchain_logger.get_chain_stats()
        return {
            "blockchain_statistics": stats,
            "storage_location": "blockchain_audit/audit_logs.json"
        }
    except Exception as e:
        print(f"Error in get_blockchain_stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/resource/{resource_name}")
def get_resource_audit_history(resource_name: str):
    """
    Get audit history for a specific resource
    
    Shows all compliance checks for a single resource over time
    """
    try:
        chain = blockchain_logger.get_audit_trail(resource_name=resource_name)
        
        # Filter out genesis block
        audit_blocks = [block for block in chain if block.get("id", 0) > 0]
        
        if not audit_blocks:
            return {
                "resource_name": resource_name,
                "total_audits": 0,
                "message": "No audit history found for this resource",
                "history": []
            }
        
        return {
            "resource_name": resource_name,
            "total_audits": len(audit_blocks),
            "history": audit_blocks
        }
    except Exception as e:
        print(f"Error in get_resource_audit_history: {e}")
        raise HTTPException(status_code=500, detail=str(e))
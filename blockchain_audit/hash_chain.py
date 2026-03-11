"""
Blockchain-based Tamper-Proof Audit Logging
Implements a simple but effective blockchain for compliance audit trails
"""
import json
import hashlib
from datetime import datetime
from typing import List, Dict, Optional
from pathlib import Path

class BlockchainAuditLogger:
    """
    Blockchain implementation for tamper-proof compliance logging
    
    Features:
    - SHA-256 hash chain
    - Immutable audit records
    - Integrity verification
    - Timestamp tracking
    """
    
    def __init__(self, log_file: str = "blockchain-audit/audit_logs.json"):
        """
        Initialize blockchain logger
        
        Args:
            log_file: Path to blockchain storage file
        """
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(exist_ok=True, parents=True)
        
        # Initialize blockchain if doesn't exist
        if not self.log_file.exists():
            self._initialize_blockchain()
    
    def _initialize_blockchain(self):
        """Create genesis block (first block in chain)"""
        genesis_block = {
            "id": 0,
            "timestamp": datetime.now().isoformat(),
            "data": {
                "message": "Genesis Block - CloudTwin AI Compliance Audit Chain",
                "version": "1.0.0"
            },
            "previous_hash": "0",
            "current_hash": self._calculate_hash(0, "Genesis Block", "0")
        }
        self._save_chain([genesis_block])
        print("🔐 Blockchain initialized with genesis block")
    
    def _calculate_hash(self, block_id: int, data: str, previous_hash: str) -> str:
        """
        Calculate SHA-256 hash for a block
        
        Args:
            block_id: Block number
            data: Block data as string
            previous_hash: Hash of previous block
            
        Returns:
            str: Calculated hash
        """
        block_string = f"{block_id}{data}{previous_hash}".encode()
        return hashlib.sha256(block_string).hexdigest()
    
    def _load_chain(self) -> List[Dict]:
        """
        Load blockchain from file
        
        Returns:
            List[Dict]: List of blocks
        """
        try:
            with open(self.log_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading blockchain: {e}")
            return []
    
    def _save_chain(self, chain: List[Dict]):
        """
        Save blockchain to file
        
        Args:
            chain: List of blocks to save
        """
        with open(self.log_file, 'w') as f:
            json.dump(chain, f, indent=2)
    
    def add_compliance_log(
        self,
        resource_name: str,
        resource_type: str,
        compliance_score: float,
        checks_passed: int,
        checks_total: int,
        check_details: Dict
    ) -> Dict:
        """
        Add new compliance check to blockchain
        
        Args:
            resource_name: Name of checked resource
            resource_type: Type of resource (e.g., 's3_bucket')
            compliance_score: Compliance score (0-100)
            checks_passed: Number of passed checks
            checks_total: Total number of checks
            check_details: Detailed check results
            
        Returns:
            Dict: The created block
        """
        chain = self._load_chain()
        
        # Get previous block
        previous_block = chain[-1] if chain else None
        previous_hash = previous_block["current_hash"] if previous_block else "0"
        
        # Create new block data
        new_id = len(chain)
        data = json.dumps({
            "resource_name": resource_name,
            "resource_type": resource_type,
            "score": compliance_score,
            "passed": checks_passed,
            "total": checks_total,
            "details": check_details
        }, sort_keys=True)
        
        current_hash = self._calculate_hash(new_id, data, previous_hash)
        
        # Create new block
        new_block = {
            "id": new_id,
            "timestamp": datetime.now().isoformat(),
            "resource_name": resource_name,
            "resource_type": resource_type,
            "compliance_score": compliance_score,
            "checks_passed": checks_passed,
            "checks_total": checks_total,
            "check_details": check_details,
            "previous_hash": previous_hash,
            "current_hash": current_hash
        }
        
        # Append and save
        chain.append(new_block)
        self._save_chain(chain)
        
        print(f"✅ Added block #{new_id} to blockchain: {resource_name} ({compliance_score}%)")
        
        return new_block
    
    def get_audit_trail(
        self,
        resource_name: Optional[str] = None,
        limit: Optional[int] = None
    ) -> List[Dict]:
        """
        Retrieve audit trail
        
        Args:
            resource_name: Optional filter by resource name
            limit: Optional limit number of results
            
        Returns:
            List[Dict]: List of audit log entries
        """
        chain = self._load_chain()
        
        # Filter by resource name if specified
        if resource_name:
            chain = [block for block in chain if block.get("resource_name") == resource_name]
        
        # Apply limit if specified
        if limit:
            chain = chain[-limit:]
        
        return chain
    
    def verify_chain_integrity(self) -> tuple[bool, Optional[str]]:
        """
        Verify blockchain hasn't been tampered with
        
        Returns:
            tuple: (is_valid, error_message)
        """
        chain = self._load_chain()
        
        if len(chain) == 0:
            return False, "Empty blockchain"
        
        # Check each block
        for i in range(1, len(chain)):
            current_block = chain[i]
            previous_block = chain[i - 1]
            
            # Verify previous hash matches
            if current_block["previous_hash"] != previous_block["current_hash"]:
                return False, f"Hash mismatch at block {i}"
            
            # Verify current hash is correct
            data = json.dumps({
                "resource_name": current_block.get("resource_name", ""),
                "resource_type": current_block.get("resource_type", ""),
                "score": current_block.get("compliance_score", 0),
                "passed": current_block.get("checks_passed", 0),
                "total": current_block.get("checks_total", 0),
                "details": current_block.get("check_details", {})
            }, sort_keys=True)
            
            calculated_hash = self._calculate_hash(
                current_block["id"],
                data,
                current_block["previous_hash"]
            )
            
            if current_block["current_hash"] != calculated_hash:
                return False, f"Invalid hash at block {i}"
        
        return True, None
    
    def get_chain_stats(self) -> Dict:
        """
        Get blockchain statistics
        
        Returns:
            Dict: Statistics about the blockchain
        """
        chain = self._load_chain()
        
        if len(chain) <= 1:  # Only genesis block
            return {
                "total_blocks": len(chain),
                "total_audits": 0,
                "average_compliance": 0,
                "chain_valid": True
            }
        
        # Calculate stats (skip genesis block)
        audit_blocks = [b for b in chain if b.get("id", 0) > 0]
        total_score = sum(b.get("compliance_score", 0) for b in audit_blocks)
        avg_compliance = total_score / len(audit_blocks) if audit_blocks else 0
        
        is_valid, _ = self.verify_chain_integrity()
        
        return {
            "total_blocks": len(chain),
            "total_audits": len(audit_blocks),
            "average_compliance": round(avg_compliance, 2),
            "chain_valid": is_valid,
            "last_audit": audit_blocks[-1].get("timestamp") if audit_blocks else None
        }

# Global blockchain logger instance
blockchain_logger = BlockchainAuditLogger()
"""
Blockchain-based Tamper-Proof Audit Logging
Implements SHA-256 + Merkle Tree for tamper-proof compliance audit trails
"""
import json
import hashlib
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from pathlib import Path


class MerkleTree:
    """
    Merkle Tree implementation using SHA-256 hashing.

    Provides cryptographic proof of data inclusion via Merkle proofs,
    enabling efficient and tamper-proof verification of audit log entries.
    """

    def __init__(self, leaves: Optional[List[str]] = None):
        self._leaves: List[str] = []
        self._tree: List[List[str]] = []
        if leaves:
            for leaf in leaves:
                self._leaves.append(leaf)
            self._build()

    @staticmethod
    def _hash(data: str) -> str:
        """Compute SHA-256 hash of a string."""
        return hashlib.sha256(data.encode()).hexdigest()

    @staticmethod
    def _hash_pair(left: str, right: str) -> str:
        """Compute SHA-256 hash of two concatenated hashes."""
        return hashlib.sha256((left + right).encode()).hexdigest()

    def _build(self):
        """Build (or rebuild) the full Merkle Tree from the current leaves."""
        if not self._leaves:
            self._tree = []
            return

        # Level 0 = hashed leaves
        level = [self._hash(leaf) for leaf in self._leaves]
        self._tree = [level]

        # Build successive levels until we reach the root
        while len(level) > 1:
            next_level = []
            for i in range(0, len(level), 2):
                left = level[i]
                # If odd number of nodes, duplicate the last one
                right = level[i + 1] if i + 1 < len(level) else level[i]
                next_level.append(self._hash_pair(left, right))
            self._tree.append(next_level)
            level = next_level

    def add_leaf(self, data: str):
        self._leaves.append(data)
        self._build()

    def get_root_hash(self) -> Optional[str]:
        """Return the Merkle root hash, or None if the tree is empty."""
        if not self._tree:
            return None
        return self._tree[-1][0]

    def get_proof(self, index: int) -> List[Tuple[str, str]]:
        """
        Return the Merkle proof (list of sibling hashes) for the leaf at *index*.

        Each element is a tuple of (direction, hash) where direction is 'left'
        or 'right', indicating which side the sibling sits on.
        """
        if index < 0 or index >= len(self._leaves):
            raise IndexError(f"Leaf index {index} out of range (0-{len(self._leaves) - 1})")

        proof: List[Tuple[str, str]] = []
        for level in self._tree[:-1]:  # skip the root level
            if index % 2 == 0:
                # sibling is to the right
                sibling_index = index + 1
                direction = "right"
            else:
                # sibling is to the left
                sibling_index = index - 1
                direction = "left"

            if sibling_index < len(level):
                proof.append((direction, level[sibling_index]))
            else:
                # odd node duplicated -- sibling is itself
                proof.append((direction, level[index]))

            # move to parent index
            index //= 2

        return proof

    @staticmethod
    def verify_proof(data: str, proof: List[Tuple[str, str]], root_hash: str) -> bool:
        """Verify that *data* is included in the tree with the given *root_hash*."""
        current = hashlib.sha256(data.encode()).hexdigest()

        for direction, sibling_hash in proof:
            if direction == "right":
                current = hashlib.sha256((current + sibling_hash).encode()).hexdigest()
            else:  # left
                current = hashlib.sha256((sibling_hash + current).encode()).hexdigest()

        return current == root_hash

    @property
    def leaf_count(self) -> int:
        """Return the number of leaves in the tree."""
        return len(self._leaves)

    def get_leaves(self) -> List[str]:
        """Return a copy of the raw leaf data list."""
        return list(self._leaves)


class BlockchainAuditLogger:
    """
    Blockchain implementation for tamper-proof compliance logging

    Features:
    - SHA-256 hash chain
    - Merkle Tree for efficient inclusion proofs
    - Immutable audit records
    - Integrity verification
    - Timestamp tracking
    """

    def __init__(self, log_file: str = "blockchain_audit/audit_logs.json"):
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(exist_ok=True, parents=True)

        self.merkle_tree = MerkleTree()

        if not self.log_file.exists():
            self._initialize_blockchain()
        else:
            self._rebuild_merkle_tree()

    def _rebuild_merkle_tree(self):
        """Rebuild the Merkle Tree from all block hashes in the existing chain."""
        chain = self._load_chain()
        self.merkle_tree = MerkleTree()
        for block in chain:
            self.merkle_tree.add_leaf(block["current_hash"])

    def _initialize_blockchain(self):
        """Create genesis block (first block in chain)."""
        genesis_hash = self._calculate_hash(0, "Genesis Block", "0")

        genesis_block = {
            "id": 0,
            "timestamp": datetime.now().isoformat(),
            "data": {
                "message": "Genesis Block - CloudTwin AI Compliance Audit Chain",
                "version": "1.0.0"
            },
            "previous_hash": "0",
            "current_hash": genesis_hash,
            "merkle_root": None
        }

        self.merkle_tree.add_leaf(genesis_hash)
        genesis_block["merkle_root"] = self.merkle_tree.get_root_hash()

        self._save_chain([genesis_block])
        print("Blockchain initialized with genesis block")

    def _calculate_hash(self, block_id: int, data: str, previous_hash: str) -> str:
        """Calculate SHA-256 hash for a block."""
        block_string = f"{block_id}{data}{previous_hash}".encode()
        return hashlib.sha256(block_string).hexdigest()

    def _load_chain(self) -> List[Dict]:
        try:
            with open(self.log_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading blockchain: {e}")
            return []

    def _save_chain(self, chain: List[Dict]):
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
        """Add a new compliance check result as a block in the chain."""
        chain = self._load_chain()

        previous_block = chain[-1] if chain else None
        previous_hash = previous_block["current_hash"] if previous_block else "0"

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

        self.merkle_tree.add_leaf(current_hash)
        merkle_root = self.merkle_tree.get_root_hash()

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
            "current_hash": current_hash,
            "merkle_root": merkle_root
        }

        chain.append(new_block)
        self._save_chain(chain)

        print(f"Added block #{new_id} to blockchain: {resource_name} ({compliance_score}%)")

        return new_block

    def get_audit_trail(
        self,
        resource_name: Optional[str] = None,
        limit: Optional[int] = None
    ) -> List[Dict]:
        chain = self._load_chain()

        if resource_name:
            chain = [block for block in chain if block.get("resource_name") == resource_name]

        if limit:
            chain = chain[-limit:]

        return chain

    def verify_chain_integrity(self) -> tuple[bool, Optional[str]]:
        """Verify blockchain hasn't been tampered with. Returns (is_valid, error_message)."""
        chain = self._load_chain()

        if len(chain) == 0:
            return False, "Empty blockchain"

        for i in range(1, len(chain)):
            current_block = chain[i]
            previous_block = chain[i - 1]

            if current_block["previous_hash"] != previous_block["current_hash"]:
                return False, f"Hash mismatch at block {i}"

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

    def get_merkle_root(self) -> Optional[str]:
        """Return the current Merkle root hash of all block hashes."""
        return self.merkle_tree.get_root_hash()

    def get_merkle_proof(self, block_id: int) -> List[Tuple[str, str]]:
        """
        Return the Merkle proof for a specific block.

        The proof can be used to verify that a block's hash is included in the
        Merkle Tree without needing the full tree.
        """
        if block_id < 0 or block_id >= self.merkle_tree.leaf_count:
            raise ValueError(
                f"Block id {block_id} not found. "
                f"Chain has {self.merkle_tree.leaf_count} blocks (ids 0-{self.merkle_tree.leaf_count - 1})."
            )
        return self.merkle_tree.get_proof(block_id)

    def verify_merkle_proof(self, block_id: int) -> bool:
        """
        Verify that a block's hash is included in the current Merkle Tree.

        Loads the block from the chain, retrieves its Merkle proof, and
        verifies the proof against the current Merkle root.
        """
        chain = self._load_chain()
        if block_id < 0 or block_id >= len(chain):
            raise ValueError(
                f"Block id {block_id} not found. "
                f"Chain has {len(chain)} blocks (ids 0-{len(chain) - 1})."
            )

        block_hash = chain[block_id]["current_hash"]
        proof = self.merkle_tree.get_proof(block_id)
        root_hash = self.merkle_tree.get_root_hash()

        return MerkleTree.verify_proof(block_hash, proof, root_hash)

    def get_chain_stats(self) -> Dict:
        """Get blockchain statistics."""
        chain = self._load_chain()

        if len(chain) <= 1:  # Only genesis block
            return {
                "total_blocks": len(chain),
                "total_audits": 0,
                "average_compliance": 0,
                "chain_valid": True,
                "merkle_root_hash": self.merkle_tree.get_root_hash()
            }

        # Skip genesis block (id 0) when calculating audit stats
        audit_blocks = [b for b in chain if b.get("id", 0) > 0]
        total_score = sum(b.get("compliance_score", 0) for b in audit_blocks)
        avg_compliance = total_score / len(audit_blocks) if audit_blocks else 0

        is_valid, _ = self.verify_chain_integrity()

        return {
            "total_blocks": len(chain),
            "total_audits": len(audit_blocks),
            "average_compliance": round(avg_compliance, 2),
            "chain_valid": is_valid,
            "last_audit": audit_blocks[-1].get("timestamp") if audit_blocks else None,
            "merkle_root_hash": self.merkle_tree.get_root_hash()
        }

# Global blockchain logger instance
blockchain_logger = BlockchainAuditLogger()

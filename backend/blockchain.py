"""
SecureWatch Tamper-Evident Hash-Chained Audit Log
(Described accurately — NOT a distributed blockchain)

- Persists to JSON on disk
- Loads existing chain on startup
- Validates integrity on load
- Appends only on real security events
- Provides tamper-test for demo (on a copy, never the real chain)
"""
import hashlib
import json
import time
import copy
import os
import logging

from config import BLOCKCHAIN_PATH

logger = logging.getLogger("securewatch.blockchain")


class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "hash": self.hash
        }

    @classmethod
    def from_dict(cls, d):
        block = cls(d["index"], d["timestamp"], d["data"], d["previous_hash"])
        # Don't recalculate — keep stored hash for validation
        block.hash = d["hash"]
        return block


class Blockchain:
    def __init__(self, path=None):
        self.path = path or BLOCKCHAIN_PATH
        self.chain = []
        self._tamper_copy = None  # For demo tamper test
        self._load_or_create()

    def _load_or_create(self):
        """Load existing chain from disk, validate it, or create new genesis."""
        if os.path.exists(self.path):
            try:
                with open(self.path, "r") as f:
                    chain_data = json.load(f)
                if chain_data and len(chain_data) > 0:
                    self.chain = [Block.from_dict(b) for b in chain_data]
                    if self.is_chain_valid():
                        logger.info(
                            f"Loaded {len(self.chain)} blocks from disk — chain valid"
                        )
                        return
                    else:
                        logger.warning(
                            "Chain on disk is INVALID — archiving and starting fresh"
                        )
                        # Archive the corrupted file
                        backup = self.path + f".invalid.{int(time.time())}"
                        os.rename(self.path, backup)
            except (json.JSONDecodeError, KeyError, TypeError) as e:
                logger.warning(f"Failed to load chain: {e} — creating new genesis")

        # Create fresh genesis
        self.chain = [self._create_genesis_block()]
        self.save_chain()

    def _create_genesis_block(self):
        return Block(0, time.time(), {"message": "Genesis Block — SecureWatch Audit Log"}, "0")

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, data):
        """Add a new block and persist immediately."""
        previous_block = self.get_latest_block()
        new_block = Block(
            len(self.chain),
            time.time(),
            data,
            previous_block.hash
        )
        self.chain.append(new_block)
        self.save_chain()
        logger.info(f"Block #{new_block.index} added: {data.get('event', 'N/A')}")
        return new_block.to_dict()

    def save_chain(self):
        """Persist chain to disk."""
        chain_data = [block.to_dict() for block in self.chain]
        # Write atomically
        tmp_path = self.path + ".tmp"
        with open(tmp_path, "w") as f:
            json.dump(chain_data, f, indent=2)
        os.replace(tmp_path, self.path)

    def is_chain_valid(self):
        """Validate the entire chain — returns (valid, broken_index)."""
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            expected_hash = current.calculate_hash()
            if current.hash != expected_hash:
                return False
            if current.previous_hash != previous.hash:
                return False
        # Also check genesis hash
        if len(self.chain) > 0:
            genesis = self.chain[0]
            if genesis.hash != genesis.calculate_hash():
                return False
        return True

    def validate_detailed(self):
        """Return detailed validation info for the dashboard."""
        errors = []
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            expected_hash = current.calculate_hash()
            if current.hash != expected_hash:
                errors.append({
                    "block_index": i,
                    "error": "Hash mismatch",
                    "stored": current.hash[:16] + "...",
                    "expected": expected_hash[:16] + "..."
                })
            if current.previous_hash != previous.hash:
                errors.append({
                    "block_index": i,
                    "error": "Previous hash mismatch",
                    "stored_prev": current.previous_hash[:16] + "...",
                    "actual_prev": previous.hash[:16] + "..."
                })
        return {
            "valid": len(errors) == 0,
            "total_blocks": len(self.chain),
            "errors": errors
        }

    def get_chain_data(self):
        """Return all blocks as dicts."""
        return [block.to_dict() for block in self.chain]

    # ----------------------------------
    # Tamper Test (for demo, never touches real chain)
    # ----------------------------------

    def start_tamper_test(self, block_index=None):
        """Create a copy and tamper with one block for demo."""
        self._tamper_copy = [copy.deepcopy(b.to_dict()) for b in self.chain]
        if block_index is None:
            block_index = max(1, len(self.chain) - 1)
        if block_index < len(self._tamper_copy):
            self._tamper_copy[block_index]["data"]["TAMPERED"] = True
            self._tamper_copy[block_index]["data"]["original_event"] = \
                self._tamper_copy[block_index]["data"].get("event", "unknown")
            self._tamper_copy[block_index]["data"]["event"] = "TAMPERED_BY_DEMO"
            # Recalculate hash for this block to show it no longer matches
            # Actually, DON'T recalculate — leave the old hash so validation fails
        return {
            "tampered_block_index": block_index,
            "message": "Tamper test active — call /api/v1/ledger/verify?tamper=true to see the broken chain"
        }

    def validate_tamper_copy(self):
        """Validate the tampered copy to show it fails."""
        if not self._tamper_copy:
            return {"valid": True, "message": "No tamper test active"}

        errors = []
        for i in range(len(self._tamper_copy)):
            block = self._tamper_copy[i]
            # Recalculate what hash should be
            expected = hashlib.sha256(json.dumps({
                "index": block["index"],
                "timestamp": block["timestamp"],
                "data": block["data"],
                "previous_hash": block["previous_hash"]
            }, sort_keys=True).encode()).hexdigest()

            if block["hash"] != expected:
                errors.append({
                    "block_index": i,
                    "error": "TAMPER DETECTED — hash does not match block content",
                    "stored_hash": block["hash"][:16] + "...",
                    "computed_hash": expected[:16] + "..."
                })

            if i > 0:
                if block["previous_hash"] != self._tamper_copy[i - 1]["hash"]:
                    errors.append({
                        "block_index": i,
                        "error": "Chain link broken — previous_hash mismatch"
                    })

        return {
            "valid": len(errors) == 0,
            "total_blocks": len(self._tamper_copy),
            "errors": errors,
            "tampered": True
        }

    def reset_tamper_test(self):
        """Clear the tamper copy."""
        self._tamper_copy = None
        return {"message": "Tamper test reset — real chain unaffected"}

    def reset_chain(self):
        """Reset the real chain back to a single Genesis block and persist."""
        self.chain = [self._create_genesis_block()]
        self.save_chain()
        self._tamper_copy = None
        logger.info("Blockchain reset to Genesis block.")
        return {
            "status": "SUCCESS",
            "message": "Blockchain ledger successfully reset to Genesis block",
            "total_blocks": len(self.chain)
        }

    def display_chain(self):
        """Legacy console display."""
        print("\n========== HASH-CHAINED AUDIT LOG ==========\n")
        for block in self.chain:
            print(f"Block: {block.index}")
            print(f"Data: {block.data}")
            print(f"Hash: {block.hash}")
            print("-" * 40)
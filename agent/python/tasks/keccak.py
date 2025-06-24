from typing import List
from .base import TaskHandler


class KeccakTask(TaskHandler):
    """Task handler for KECCAK operations."""
    
    def run(self, inputs: List[bytes]) -> bytes:
        """
        Execute KECCAK operation on keccak request data.
        
        Args:
            inputs (List[bytes]): Keccak request data (expects exactly one input)
            
        Returns:
            bytes: The keccak receipt
        """
        assert len(inputs) == 1, "KECCAK task expects exactly one input"
        return self._call_rust_binary("KECCAK", inputs)

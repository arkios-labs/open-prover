from typing import List
from .base import TaskHandler


class SnarkTask(TaskHandler):
    """Task handler for SNARK operations."""
    
    def run(self, inputs: List[bytes]) -> bytes:
        """
        Execute SNARK operation on rollup receipt data.
        
        Args:
            inputs (List[bytes]): Rollup receipt data
            
        Returns:
            bytes: The SNARK receipt
        """
        assert len(inputs) == 1, "SNARK task expects exactly one input"
        return self._call_rust_binary("SNARK", inputs)

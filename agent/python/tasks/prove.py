from typing import List
from .base import TaskHandler


class ProveTask(TaskHandler):
    """Task handler for PROVE operations."""
    
    def run(self, inputs: List[bytes]) -> bytes:
        """
        Execute PROVE operation on segment data.
        
        Args:
            inputs (List[bytes]): Segment data to prove
            
        Returns:
            bytes: The proof receipt
        """
        assert len(inputs) == 1, "PROVE task expects exactly one input"
        return self._call_rust_binary("PROVE", inputs)
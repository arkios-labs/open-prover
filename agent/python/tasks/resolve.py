from typing import List
from .base import TaskHandler


class ResolveTask(TaskHandler):
    """Task handler for RESOLVE operations."""
    
    def run(self, inputs: List[bytes]) -> bytes:
        """
        Execute RESOLVE operation on resolve input data.
        
        Args:
            inputs (List[bytes]): Resolve input containing root, union, and assumptions
            
        Returns:
            bytes: The resolved receipt
        """
        assert len(inputs) == 1, "RESOLVE task expects exactly one input"
        return self._call_rust_binary("RESOLVE", inputs)

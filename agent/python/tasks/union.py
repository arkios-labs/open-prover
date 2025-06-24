from typing import List
from .base import TaskHandler


class UnionTask(TaskHandler):
    """Task handler for UNION operations."""
    
    def run(self, inputs: List[bytes]) -> bytes:
        """
        Execute UNION operation on two receipts.
        
        Args:
            inputs (List[bytes]): Two receipts to union (expects exactly two inputs)
            
        Returns:
            bytes: The unioned receipt
        """
        assert len(inputs) == 2, "UNION task expects exactly two inputs"
        return self._call_rust_binary("UNION", inputs)

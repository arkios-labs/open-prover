from typing import List

from .base import TaskHandler


class JoinTask(TaskHandler):
    """Task handler for JOIN operations."""
    
    def run(self, inputs: List[bytes]) -> bytes:
        """
        Execute JOIN operation on two receipts.
        
        Args:
            inputs (List[bytes]): Exactly two receipts to join
            
        Returns:
            bytes: The joined receipt
        """
        assert len(inputs) == 2, "JOIN task expects exactly two inputs"
        return self._call_rust_binary("JOIN", inputs)
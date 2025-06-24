from typing import List
from .base import TaskHandler


class FinalizeTask(TaskHandler):
    """Task handler for FINALIZE operations."""
    
    def run(self, inputs: List[bytes]) -> bytes:
        """
        Execute FINALIZE operation on finalize input data.
        
        Args:
            inputs (List[bytes]): Finalize input containing root receipt, journal, and image_id
            
        Returns:
            bytes: The final STARK receipt
        """
        assert len(inputs) == 1, "FINALIZE task expects exactly one input"
        return self._call_rust_binary("FINALIZE", inputs)

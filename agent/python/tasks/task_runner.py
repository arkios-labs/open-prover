# tasks/task_runner.py
from typing import List
from .task_registry import get_task_handler
from common.types import TaskType


def run_task(task_type: str, inputs: List[bytes]) -> bytes:
    """
    Run a task of the specified type with the given inputs.
    
    Args:
        task_type (str): The type of task to run (e.g., "JOIN", "UNION", etc.)
        inputs (List[bytes]): Input data for the task
        
    Returns:
        bytes: Output from the task
    """
    task_type = task_type.upper()
    handler = get_task_handler(task_type)
    return handler.run(inputs)

try:
    import ray
    
    @ray.remote
    def run_task_remote(task_type: str, inputs: List[bytes]) -> bytes:
        """
        Remote version of run_task for distributed execution.
        """
        return run_task(task_type, inputs)
        
except ImportError:
    def run_task_remote(task_type: str, inputs: List[bytes]) -> bytes:
        """
        Fallback version when Ray is not available.
        """
        return run_task(task_type, inputs)

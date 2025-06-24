from .base import TaskHandler
from .join import JoinTask
from .prove import ProveTask
from .keccak import KeccakTask
from .union import UnionTask
from .resolve import ResolveTask
from .finalize import FinalizeTask
from .snark import SnarkTask


TASK_HANDLERS = {
    "JOIN": JoinTask,
    "PROVE": ProveTask,
    "KECCAK": KeccakTask,
    "UNION": UnionTask,
    "RESOLVE": ResolveTask,
    "FINALIZE": FinalizeTask,
    "SNARK": SnarkTask,
}


def get_task_handler(task_type: str) -> TaskHandler:
    """Get the appropriate task handler for the given task type."""
    handler_class = TASK_HANDLERS.get(task_type.upper())
    if handler_class is None:
        raise ValueError(f"Unknown task type: {task_type}")
    return handler_class()

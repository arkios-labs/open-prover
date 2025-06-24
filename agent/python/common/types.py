from enum import Enum


class TaskType(Enum):
    """Enumeration of supported task types."""
    JOIN = "JOIN"
    UNION = "UNION"
    PROVE = "PROVE"
    KECCAK = "KECCAK"
    RESOLVE = "RESOLVE"
    FINALIZE = "FINALIZE"
    SNARK = "SNARK"

    @classmethod
    def has_value(cls, value: str) -> bool:
        return value.upper() in cls._value2member_map_
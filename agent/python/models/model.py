from typing import List, Optional, Any, Dict, Set

from pydantic import BaseModel, Field


class PrePostValue(BaseModel):
    pc: int = Field(...)
    merkle_root: List[int] = Field(...)


class PrePost(BaseModel):
    Value: PrePostValue = Field(...)


class Input(BaseModel):
    Pruned: List[int] = Field(...)


class AssumptionValue(BaseModel):
    claim: List[int] = Field(...)
    control_root: List[int] = Field(...)


class Assumption(BaseModel):
    Value: AssumptionValue = Field(...)


class Assumptions(BaseModel):
    Value: List[Assumption] = Field(...)


class Journal(BaseModel):
    Value: List[Any] = Field(...)


class OutputValue(BaseModel):
    journal: Journal = Field(...)
    assumptions: Assumptions = Field(...)


class Output(BaseModel):
    Value: Optional[OutputValue] = Field(None)


class ClaimValue(BaseModel):
    pre: PrePost = Field(...)
    post: PrePost = Field(...)
    exit_code: Any = Field(...)
    input: Input = Field(...)
    output: Output = Field(...)


class Claim(BaseModel):
    Value: ClaimValue = Field(...)


class ControlInclusionProof(BaseModel):
    index: int = Field(...)
    digests: List[List[int]] = Field(...)


class LiftedReceipt(BaseModel):
    seal: List[int] = Field(...)
    control_id: List[int] = Field(...)
    claim: Claim = Field(...)
    hashfn: str = Field(...)
    verifier_parameters: List[int] = Field(...)
    control_inclusion_proof: ControlInclusionProof = Field(...)


class Digest(BaseModel):
    digests: List[List[int]] = Field(...)


class MemoryImage(BaseModel):
    pages: Dict[int, List[int]]  # Maps page ID to content (int list)
    digests: Dict[str, List[int]] = Field(...)  # Changed from List to Dict
    dirty: Set[int]


class TerminateState(BaseModel):
    a0: List[int]
    a1: List[int]


class InnerClaim(BaseModel):
    pre_state: List[int]
    post_state: List[int]
    input: List[int]
    output: Optional[List[int]] = None  # Changed from List to Optional[List]
    terminate_state: Optional[TerminateState] = None
    shutdown_cycle: Optional[Any] = None


class Inner(BaseModel):
    partial_image: MemoryImage
    claim: InnerClaim
    read_record: List[List[int]]
    write_record: List[Any]
    suspend_cycle: int
    paging_cycles: int
    segment_threshold: int
    po2: int
    index: int


class OutputAssumptionValue(BaseModel):
    claim: Optional[List[int]] = None
    control_root: Optional[List[int]] = None


class OutputAssumption(BaseModel):
    value: Optional[OutputAssumptionValue] = None


class SegmentOutput(BaseModel):
    journal: Optional[Dict[str, List[Any]]] = None
    assumptions: Optional[Dict[str, List[OutputAssumption]]] = None


class Segment(BaseModel):
    index: int
    inner: Inner
    output: Optional[SegmentOutput] = None


class UnresolvedAssumption(BaseModel):
    claim: List[int]
    control_root: List[int]


# Session에서 사용하는 Assumption (기존 Assumption과 다른 구조)
class SessionAssumption(BaseModel):
    claim: Optional[List[int]] = None
    control_root: Optional[List[int]] = None
    Unresolved: Optional[UnresolvedAssumption] = Field(None)


# Rust: KeccakState = [u64; 25]
class KeccakState(BaseModel):
    state: List[int]  # 25개의 u64 값


class SerializableKeccakRequest(BaseModel):
    claim_digest: List[int]  # Digest
    po2: int  # usize
    control_root: List[int]  # Digest
    input: List[List[int]]  # Vec<[u64; 25]> - 각 내부 리스트는 25개의 정수


class KeccakReceiptClaim(BaseModel):
    Pruned: List[int] = Field(...)  # []int64 -> List[int]


class KeccakReceiptControlInclusionProof(BaseModel):
    index: int
    digests: List[List[int]]  # [][]int


class KeccakReceipt(BaseModel):
    seal: List[int]  # []int
    control_id: List[int]  # []int
    claim: KeccakReceiptClaim
    hashfn: str
    verifier_parameters: List[int]  # []int64 -> List[int]
    control_inclusion_proof: KeccakReceiptControlInclusionProof


class ResolveInput(BaseModel):
    root: Any  # SuccinctReceipt<ReceiptClaim> (dict)
    union: Optional[Any] = None  # SuccinctReceipt<Unknown> (dict)
    assumptions: List[Any]  # List[Any] - 실제 데이터 구조에 따라 유연하게 처리


class FinalizeInput(BaseModel):
    root: Any  # SuccinctReceipt<ReceiptClaim> (dict)
    journal: List[int]  # Vec<u8> -> List[int] (바이트 배열)
    image_id: str  # Digest (32 bytes as int array)


class Session(BaseModel):
    segments: List[Segment]
    journal: Dict[str, List[Any]]
    assumptions: List[List[SessionAssumption]]  # SessionAssumption으로 변경
    pending_zkrs: List[Any]
    pending_keccaks: List[SerializableKeccakRequest]

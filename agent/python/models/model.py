from typing import List, Optional, Any, Dict, Set, Union

from pydantic import BaseModel, Field

class PrePostValue(BaseModel):
    pc: int = Field(..., alias="pc")
    merkle_root: List[int] = Field(..., alias="merkle_root")

class PrePost(BaseModel):
    value: PrePostValue = Field(..., alias="Value")


class Input(BaseModel):
    pruned: List[int] = Field(..., alias="Pruned")


class AssumptionValue(BaseModel):
    claim: List[int] = Field(..., alias="claim")
    control_root: List[int] = Field(..., alias="control_root")


class Assumption(BaseModel):
    value: AssumptionValue = Field(..., alias="Value")


class Assumptions(BaseModel):
    value: List[Assumption] = Field(..., alias="Value")


class Journal(BaseModel):
    value: List[Any] = Field(..., alias="Value")


class OutputValue(BaseModel):
    journal: Journal = Field(..., alias="journal")
    assumptions: Assumptions = Field(..., alias="assumptions")


class Output(BaseModel):
    value: Optional[OutputValue] = Field(None, alias="Value")


class ClaimValue(BaseModel):
    pre: PrePost = Field(..., alias="pre")
    post: PrePost = Field(..., alias="post")
    exit_code: Any = Field(..., alias="exit_code")
    input: Input = Field(..., alias="input")
    output: Output = Field(..., alias="output")


class Claim(BaseModel):
    value: ClaimValue = Field(..., alias="Value")

class ControlInclusionProof(BaseModel):
    index: int = Field(..., alias="index")
    digests: List[List[int]] = Field(..., alias="digests")

class LiftedReceipt(BaseModel):
    seal: List[int] = Field(..., alias="seal")
    control_id: List[int] = Field(..., alias="control_id")
    claim: Claim = Field(..., alias="claim")
    hashfn: str = Field(..., alias="hashfn")
    verifier_parameters: List[int] = Field(..., alias="verifier_parameters")
    control_inclusion_proof: ControlInclusionProof = Field(..., alias="control_inclusion_proof")


class Digest(BaseModel):
    digests: List[List[int]] = Field(..., alias="digests")


class MemoryImage(BaseModel):
    pages: Dict[int, List[int]]  # Maps page ID to content (int list)
    digests: Dict[str, List[int]] = Field(..., alias="digests")  # Changed from List to Dict
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
    unresolved: Optional[UnresolvedAssumption] = None
    Unresolved: Optional[UnresolvedAssumption] = None  # 실제 JSON에서 사용하는 키


# Rust: KeccakState = [u64; 25]
class KeccakState(BaseModel):
    state: List[int]  # 25개의 u64 값


# Rust: ProveKeccakRequestLocal
class ProveKeccakRequestLocal(BaseModel):
    claim_digest: List[int]  # Digest (32 bytes as int array)
    po2: int  # usize
    control_root: List[int]  # Digest (32 bytes as int array)
    input: List[List[int]]  # Vec<[u64; 25]> - 각 내부 리스트는 25개의 정수


class SerializableKeccakRequest(BaseModel):
    claim_digest: List[int]  # Digest
    po2: int  # usize
    control_root: List[int]  # Digest
    input: List[List[int]]  # Vec<[u64; 25]> - 각 내부 리스트는 25개의 정수


class KeccakReceiptClaim(BaseModel):
    pruned: List[int] = Field(..., alias="Pruned")  # []int64 -> List[int]


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


# 기존 PendingKeccak을 SerializableKeccakRequest로 변경
PendingKeccak = SerializableKeccakRequest


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

def convert_keccak_request_to_local(keccak_req: SerializableKeccakRequest) -> ProveKeccakRequestLocal:
    """Convert SerializableKeccakRequest to ProveKeccakRequestLocal format."""
    # claim_digest와 control_root는 이미 올바른 형식이므로 그대로 사용
    # (32개의 정수 배열로 표현된 Digest)

    return ProveKeccakRequestLocal(
        claim_digest=keccak_req.claim_digest,
        po2=keccak_req.po2,
        control_root=keccak_req.control_root,
        input=keccak_req.input
    )

def clean_none(obj):
    """Recursively remove None values from dict/list"""
    if isinstance(obj, dict):
        return {k: clean_none(v) for k, v in obj.items() if v is not None}
    elif isinstance(obj, list):
        return [clean_none(x) for x in obj if x is not None]
    else:
        return obj

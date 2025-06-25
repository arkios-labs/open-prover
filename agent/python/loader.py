import json
from typing import List

from models.model import LiftedReceipt, SerializableKeccakRequest, KeccakReceipt, convert_keccak_request_to_local


def load_session() -> dict:
    with open("../metadata/session/session_4_segments.json", "r") as f:
        return json.load(f)

def load_lifted_receipts() -> List[bytes]:
    with open("../metadata/lifted_receipts.json", "r") as f:
        raw_data = json.load(f)
    parsed = [LiftedReceipt.model_validate(entry) for entry in raw_data]
    return [p.model_dump_json(by_alias=True).encode() for p in parsed]


def load_keccak_requests() -> List[bytes]:
    session = load_session()
    keccak_requests = []
    
    for keccak_req_data in session.get("pending_keccaks", []):
        keccak_req = SerializableKeccakRequest.model_validate(keccak_req_data)
        
        # ProveKeccakRequestLocal 형식으로 변환
        local_req = convert_keccak_request_to_local(keccak_req)
        
        keccak_json = local_req.model_dump_json(by_alias=True)
        keccak_requests.append(keccak_json.encode())
    
    return keccak_requests


def load_keccak_receipts() -> List[bytes]:
    with open("../metadata/keccak/keccak_receipts.json", "r") as f:
        raw_data = json.load(f)
    
    keccak_receipts = []
    for receipt_data in raw_data:
        receipt = KeccakReceipt.model_validate(receipt_data)
        
        receipt_json = receipt.model_dump_json(by_alias=True)
        keccak_receipts.append(receipt_json.encode())
    
    return keccak_receipts


def load_root_receipt() -> dict:
    with open("../metadata/root_receipt.json", "r") as f:
        return json.load(f)


def load_unioned_receipt() -> dict:
    with open("../metadata/keccak/unioned_receipt.json", "r") as f:
        return json.load(f)


def load_assumption_receipts_from_session() -> List[dict]:
    session = load_session()

    
    assumptions = []
    
    for group in session.get("assumptions", []):
        for assumption_data in group:
            if isinstance(assumption_data, dict):
                cleaned_dict = {k: v for k, v in assumption_data.items() if v is not None}
                assumptions.append(cleaned_dict)
    
    print(f"Found {len(assumptions)} assumptions in session data")
    if assumptions:
        print(f"First assumption keys: {list(assumptions[0].keys())}")
    
    return assumptions


def load_segments_directly() -> List[bytes]:
    with open("../metadata/session/session_4_segments.json", "r") as f:
        raw_data = json.load(f)
    
    if isinstance(raw_data, dict) and "segments" in raw_data:
        segments = raw_data["segments"]
        segments_data = []
        for segment in segments:
            segment_json = json.dumps(segment)
            segments_data.append(segment_json.encode())
        return segments_data
    else:
        raise ValueError("No segments found in session data")


def load_session_with_segments() -> List[bytes]:
    try:
        return load_segments_directly()
    except Exception as e:
        print(f"Direct loading failed: {e}")
        print("Trying with Session models...")
        
        session = load_session()
        segments_data = []
        for segment in session.get("segments", []):
            segment_json = json.dumps(segment)
            segments_data.append(segment_json.encode())
        return segments_data


def load_resolved_receipt() -> dict:
    with open("../metadata/resolved_receipt.json", "r") as f:
        return json.load(f)
import json
from typing import List

from models.model import LiftedReceipt, SerializableKeccakRequest, KeccakReceipt
from pathlib import Path


def load_session(po2: int, cycle: int) -> dict:
    session_dir = Path(f"../metadata/po2_{po2}/session")
    pattern = f"po2_{po2}_cycle_{cycle}_*.json"

    matches = list(session_dir.glob(pattern))

    if not matches:
        raise FileNotFoundError(f"No matching session file for po2={po2}, cycle={cycle} in {session_dir}")
    if len(matches) > 1:
        print(f"Warning: multiple matches found, using the first: {matches}")

    path = matches[0]
    with open(path, "r") as f:
        return json.load(f)


def load_lifted_receipts(po2: int, cycle: int) -> List[bytes]:
    path = Path(f"../metadata/po2_{po2}/lifted_receipts_po2_{po2}_cycle_{cycle}.json")
    with open(path, "r") as f:
        raw_data = json.load(f)

    parsed = [LiftedReceipt.model_validate(entry) for entry in raw_data]
    return [p.model_dump_json(by_alias=True).encode() for p in parsed]


def load_keccak_requests(po2: int, cycle: int) -> List[bytes]:
    session = load_session(po2, cycle)
    keccak_requests = []

    for keccak_req_data in session.get("pending_keccaks", []):
        keccak_req = SerializableKeccakRequest.model_validate(keccak_req_data)
        keccak_json = keccak_req.model_dump_json(by_alias=True)
        keccak_requests.append(keccak_json.encode())

    return keccak_requests


def load_keccak_receipts(po2: int, cycle: int) -> List[bytes]:
    path = Path(f"../metadata/po2_{po2}/keccak/keccak_receipts_po2_{po2}_cycle_{cycle}.json")
    with open(path, "r") as f:
        raw_data = json.load(f)

    keccak_receipts = []
    for receipt_data in raw_data:
        receipt = KeccakReceipt.model_validate(receipt_data)

        receipt_json = receipt.model_dump_json(by_alias=True)
        keccak_receipts.append(receipt_json.encode())

    return keccak_receipts


def load_root_receipt(po2: int, cycle: int) -> dict:
    path = Path(f"../metadata/po2_{po2}/root_receipt_po2_{po2}_cycle_{cycle}.json")
    with open(path, "r") as f:
        return json.load(f)


def load_unioned_receipt(po2: int, cycle: int) -> dict:
    path = Path(f"../metadata/po2_{po2}/keccak/unioned_receipts_po2_{po2}_cycle_{cycle}.json")
    with open(path, "r") as f:
        return json.load(f)


def load_segments_directly(po2: int, cycle: int) -> List[bytes]:
    session_dir = Path(f"../metadata/po2_{po2}/session")
    pattern = f"po2_{po2}_cycle_{cycle}_*.json"

    matches = list(session_dir.glob(pattern))

    if not matches:
        raise FileNotFoundError(f"No matching session file for po2={po2}, cycle={cycle} in {session_dir}")
    if len(matches) > 1:
        print(f"Warning: multiple matches found, using the first: {matches}")

    path = matches[0]

    with open(path, "r") as f:
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


def load_session_with_segments(po2: int, cycle: int) -> List[bytes]:
    try:
        return load_segments_directly(po2, cycle)
    except Exception as e:
        print(f"Direct loading failed: {e}")
        print("Trying with Session models...")

        session = load_session(po2, cycle)
        segments_data = []
        for segment in session.get("segments", []):
            segment_json = json.dumps(segment)
            segments_data.append(segment_json.encode())
        return segments_data


def load_resolved_receipt(po2: int, cycle: int) -> dict:
    path = Path(f"../metadata/po2_{po2}/resolved_receipt_po2_{po2}_cycle_{cycle}.json")
    with open(path, "r") as f:
        return json.load(f)


def load_stark_receipt(po2: int, cycle: int) -> bytes:
    path = Path(f"../metadata/po2_{po2}/result/finalized_receipt_po2_{po2}_cycle_{cycle}.json")
    with open(path, "r") as f:
        obj = json.load(f)
        return json.dumps(obj).encode("utf-8")

import sys
import os

import json
import time
from collections import deque
from typing import List

import ray

from models.verify import verify_segment_data, verify_keccak_data
from loader import load_lifted_receipts, load_session_with_segments, load_keccak_requests, load_keccak_receipts, \
    load_root_receipt, load_unioned_receipt, load_assumption_receipts_from_session, load_resolved_receipt, \
    load_session
from common.types import TaskType
from tasks.task_runner import run_task_remote
from models.model import ResolveInput, FinalizeInput

def clean_none(obj):
    """Recursively remove None values from dict/list"""
    if isinstance(obj, dict):
        return {k: clean_none(v) for k, v in obj.items() if v is not None}
    elif isinstance(obj, list):
        return [clean_none(x) for x in obj if x is not None]
    else:
        return obj


def debug_session_structure():
    """Debug function to examine the session JSON structure."""
    with open("../metadata/session/session_4_segments.json", "r") as f:
        raw_data = json.load(f)

    print("Session data type:", type(raw_data))
    if isinstance(raw_data, dict):
        print("Top-level keys:", list(raw_data.keys()))
        if "segments" in raw_data:
            segments = raw_data["segments"]
            print(f"Number of segments: {len(segments)}")
            if segments:
                print("First segment keys:", list(segments[0].keys()))
                if "inner" in segments[0]:
                    inner = segments[0]["inner"]
                    print("Inner keys:", list(inner.keys()))
                    if "partial_image" in inner:
                        partial_image = inner["partial_image"]
                        print("Partial image keys:", list(partial_image.keys()))
                        if "digests" in partial_image:
                            digests = partial_image["digests"]
                            print("Digests type:", type(digests))
                            print("Digests sample:", str(digests)[:100])


def run_join_with_ray(inputs: List[bytes]) -> bytes:
    queue = deque(inputs)
    round_num = 1

    while len(queue) > 1:
        pair = [queue.popleft(), queue.popleft()]
        future = run_task_remote.remote(TaskType.JOIN.value, pair)
        result = ray.get(future)
        queue.append(result)
        print(f"[JOIN ROUND {round_num}] success, queue size: {len(queue)}")
        round_num += 1

    return queue[0]


def run_prove_with_ray(inputs: List[bytes]) -> List[bytes]:
    """Run PROVE tasks for each segment using Ray."""
    futures = [run_task_remote.remote(TaskType.PROVE.value, [inp]) for inp in inputs]
    results = ray.get(futures)
    return results


def run_keccak_with_ray(inputs: List[bytes], output_path: str = "../metadata/keccak/keccak_receipts.json") -> List[
    bytes]:
    print(f"Ray로 KECCAK {len(inputs)}개 분산 실행 시작...")
    start_time = time.time()

    futures = [run_task_remote.remote(TaskType.KECCAK.value, [inp]) for inp in inputs]
    results = ray.get(futures)
    elapsed = time.time() - start_time

    print(f"KECCAK 실행 완료. 결과 {len(results)}개, 소요 시간: {elapsed:.2f}초")

    all_receipts = []
    for i, result in enumerate(results):
        try:
            receipt_json = result.decode()
            receipt_data = json.loads(receipt_json)
            all_receipts.append(receipt_data)
            print(f"  [{i + 1}/{len(results)}] result size: {len(result)} bytes")
        except Exception as e:
            print(f"  [{i + 1}] 결과 디코딩 실패: {e}")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(all_receipts, f, indent=2)
    print(f"모든 KECCAK receipt가 {output_path}에 저장되었습니다.")

    return results


def run_union_with_ray(inputs: List[bytes], output_path: str = "../metadata/keccak/unioned_receipt.json") -> bytes:
    print(f"Ray로 UNION {len(inputs)}개 receipt 트리 구조 실행 시작...")
    start_time = time.time()

    queue = [[receipt] for receipt in inputs]
    receipt_count = len(inputs)

    level = 0

    while len(queue) > 1:
        level += 1
        print(f"UNION Level {level}: {len(queue)} branches")

        next_level = []
        futures = []

        for i in range(0, len(queue) - 1, 2):
            left_receipt = queue[i][-1]
            right_receipt = queue[i + 1][-1]
            futures.append((i, run_task_remote.remote(TaskType.UNION.value, [left_receipt, right_receipt])))

        results = [(i, ray.get(future)) for i, future in futures]

        for i, union_result in results:
            left_branch = queue[i]
            right_branch = queue[i + 1]
            new_branch = left_branch + right_branch + [union_result]
            next_level.append(new_branch)
            print(f"  Union [{i} + {i + 1}] size: {len(union_result)} bytes")

        if len(queue) % 2 == 1:
            next_level.append(queue[-1])

        queue = next_level

    final_branch = queue[0]
    final_result = final_branch[-1]
    elapsed = time.time() - start_time

    print(f"UNION 완료: 최종 결과 크기: {len(final_result)} bytes")
    print(f"소요 시간: {elapsed:.2f}초, 총 입력 receipt: {receipt_count}개")

    try:
        receipt_json = final_result.decode()
        receipt_data = json.loads(receipt_json)

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(receipt_data, f, indent=2)
        print(f"Unioned receipt가 {output_path}에 저장되었습니다.")
    except Exception as e:
        print(f"결과 저장 실패: {e}")

    return final_result


def run_resolve_with_ray(output_path: str = "../metadata/resolved_receipt.json") -> bytes:
    print("Loading root receipt...")
    root = clean_none(load_root_receipt())
    print("Loading unioned receipt...")
    union = clean_none(load_unioned_receipt())
    print("Loading assumption receipts...")

    session = load_session()
    assumptions = []
    
    for assumption_tuple in session.get("assumptions", []):
        if isinstance(assumption_tuple, list) and len(assumption_tuple) == 2:
            assumption, receipt = assumption_tuple
            
            if isinstance(receipt, dict):
                if "seal" in receipt and "claim" in receipt:
                    cleaned_receipt = {k: v for k, v in receipt.items() if v is not None}
                    if cleaned_receipt:
                        assumptions.append(cleaned_receipt)
    
    print(f"Loaded {len(assumptions)} proven assumption receipts from session")

    resolve_input = ResolveInput(root=root, union=union, assumptions=assumptions)
    input_bytes = resolve_input.model_dump_json(by_alias=True).encode()

    print(f"ResolveInput JSON size: {len(input_bytes)} bytes")
    print(f"ResolveInput JSON preview: {input_bytes[:200]}...")

    try:
        json_str = input_bytes.decode()
        json.loads(json_str) 
        print("JSON validation passed")
    except Exception as e:
        print(f"JSON validation failed: {e}")
        with open("../metadata/debug_resolve_input.json", "w") as f:
            f.write(json_str)
        print("Debug JSON saved to ../metadata/debug_resolve_input.json")

    print("Calling RESOLVE task...")
    result = run_task_remote.remote(TaskType.RESOLVE.value, [input_bytes])
    resolved = ray.get(result)

    try:
        resolved_json = resolved.decode()
        resolved_data = json.loads(resolved_json)
        with open(output_path, "w") as f:
            json.dump(resolved_data, f, indent=2)
        print(f"Resolved receipt written to {output_path}")
    except Exception as e:
        print(f"Failed to save resolved receipt: {e}")

    return resolved


def run_finalize_with_ray(output_path: str = "../metadata/result/stark.json") -> bytes:
    print("Loading resolved receipt...")
    root = clean_none(load_resolved_receipt())
    print("Loading session and extracting journal...")

    session = load_session()
    journal_data = session.get("journal", {})

    journal_bytes = journal_data.get("bytes", [])

    if isinstance(journal_bytes, list):
        if all(isinstance(x, int) and 0 <= x <= 255 for x in journal_bytes):
            journal_ints = journal_bytes
        else:
            raise ValueError("journal.bytes must be a list of integers (0–255)")
    elif isinstance(journal_bytes, str):
        journal_ints = list(journal_bytes.encode("utf-8"))
    else:
        raise TypeError("journal.bytes must be a list of ints or a string")

    print(f"Journal loaded, size: {len(journal_ints)} bytes")

    image_id_hex = "3fe354c3604a1b33f44a76bde3ee677e0f68a1777b0f74f7658c87b49e4c4c8a"
    print(f"Image ID loaded: {image_id_hex}")

    finalize_input = FinalizeInput(root=root, journal=journal_ints, image_id=image_id_hex)
    input_bytes = finalize_input.model_dump_json(by_alias=True).encode()

    print(f"FinalizeInput JSON size: {len(input_bytes)} bytes")
    print(f"FinalizeInput JSON preview: {input_bytes[:200]}...")

    try:
        json_str = input_bytes.decode()
        json.loads(json_str)
        print("JSON validation passed")
    except Exception as e:
        print(f"JSON validation failed: {e}")
        with open("../metadata/debug_finalize_input.json", "w") as f:
            f.write(json_str)
        print("Debug JSON saved to ../metadata/debug_finalize_input.json")

    print("Calling FINALIZE task...")
    result = run_task_remote.remote(TaskType.FINALIZE.value, [input_bytes])
    stark_receipt = ray.get(result)

    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(stark_receipt)
        print(f"Final STARK receipt written to {output_path}")
    except Exception as e:
        print(f"Failed to save STARK receipt: {e}")

    return stark_receipt


def main(task_type: TaskType):
    if task_type == TaskType.JOIN:
        input_data = load_lifted_receipts()
        result = run_join_with_ray(input_data)
        with open("../metadata/root_receipt.json", "wb") as f:
            f.write(result)
        print("JOIN result saved to ../metadata/root_receipt.json")
        return result
    elif task_type == TaskType.PROVE:
        print("Debugging session structure...")
        debug_session_structure()

        print("Loading segment data...")
        input_data = load_session_with_segments()
        print(f"Loaded {len(input_data)} segments for PROVE")

        if not verify_segment_data(input_data):
            raise RuntimeError("Segment data verification failed")

        print("Running PROVE tasks...")
        results = run_prove_with_ray(input_data)

        with open("../metadata/lifted_receipts.json", "w") as f:
            json.dump([json.loads(result.decode()) for result in results], f, indent=2)
        print(f"PROVE results saved to ../metadata/lifted_receipts.json ({len(results)} segments)")
        return results
    elif task_type == TaskType.KECCAK:
        print("Starting KECCAK test...")

        print("Loading keccak request data...")
        keccak_requests = load_keccak_requests()
        print(f"Loaded {len(keccak_requests)} keccak requests")

        if not verify_keccak_data(keccak_requests):
            raise RuntimeError("Keccak data verification failed")

        print("Using Ray for distributed execution")
        results = run_keccak_with_ray(keccak_requests)

        print("KECCAK test completed successfully")
        return results
    elif task_type == TaskType.UNION:
        print("Starting UNION test...")

        print("Loading keccak receipt data...")
        keccak_receipts = load_keccak_receipts()
        print(f"Loaded {len(keccak_receipts)} keccak receipts")

        if len(keccak_receipts) == 0:
            raise RuntimeError("No keccak receipts found")

        print("Using Ray for distributed UNION execution")
        result = run_union_with_ray(keccak_receipts)

        print("UNION test completed successfully")
        return result
    elif task_type == TaskType.RESOLVE:
        print("Starting RESOLVE test...")
        result = run_resolve_with_ray()
        print("RESOLVE test completed successfully")
        return result
    elif task_type == TaskType.FINALIZE:
        print("Starting FINALIZE test...")
        result = run_finalize_with_ray()
        print("FINALIZE test completed successfully")
        return result
    else:
        raise NotImplementedError(f"Task type {task_type.value} not yet implemented in main.")


if __name__ == "__main__":
    try:
        if not ray.is_initialized():
            ray.init(ignore_reinit_error=True)
            print("Using Ray for distributed execution")
        else:
            print("Ray already initialized")
    except Exception as e:
        print(f"Ray initialization failed: {e}")
        print("Using local execution")

    raw_arg = sys.argv[1] if len(sys.argv) > 1 else "JOIN"

    try:
        task_type = TaskType(raw_arg.upper())
    except ValueError:
        print(f"Invalid task type: {raw_arg}. Must be one of {[t.value for t in TaskType]}")
        sys.exit(1)

    try:
        result = main(task_type)
        print(f"Task {task_type.value} completed successfully")

    except Exception as e:
        print(f"Task {task_type.value} failed: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)

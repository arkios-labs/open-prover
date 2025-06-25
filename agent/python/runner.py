import json
import os
import time
from collections import deque
from typing import List

import ray

from common.types import TaskType
from loader import load_root_receipt, load_unioned_receipt, load_resolved_receipt, \
    load_session
from models.model import ResolveInput, FinalizeInput, clean_none
from tasks.task_runner import run_task_remote


def run_join_with_ray(inputs: List[bytes]) -> bytes:
    queue = deque(inputs)
    round_num = 1

    while len(queue) > 1:
        print(f"[JOIN ROUND {round_num}] queue size: {len(queue)}")
        futures = []

        for i in range(0, len(queue) - 1, 2):
            pair = [queue[i], queue[i + 1]]
            futures.append((i, run_task_remote.remote(TaskType.JOIN.value, pair)))

        results = [(i, ray.get(future)) for i, future in futures]

        next_level = []
        for i, result in results:
            next_level.append(result)

        if len(queue) % 2 == 1:
            next_level.append(queue[-1])

        queue = next_level
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
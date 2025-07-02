import json
import sys

import ray

from common.types import TaskType
from loader import load_lifted_receipts, load_session_with_segments, load_keccak_requests, load_keccak_receipts
from runner import run_join_with_ray, run_prove_with_ray, run_keccak_with_ray, run_union_with_ray, \
    run_resolve_with_ray, run_finalize_with_ray, run_snark_with_ray
import time


def main(task_type: TaskType, po2: int, cycle: int):
    if task_type == TaskType.JOIN:
        start = time.time()
        input_data = load_lifted_receipts(po2, cycle)
        result = run_join_with_ray(input_data)
        file_name = f"../metadata/po2_{po2}/root_receipt_po2_{po2}_cycle_{cycle}.json"
        with open(file_name, "wb") as f:
            f.write(result)

        print("JOIN result saved to ../metadata/root_receipt.json")
        print(f"Elapsed time: {time.time() - start:.2f} seconds")
        return result
    elif task_type == TaskType.PROVE:
        start = time.time()

        print("Loading segment data...")
        input_data = load_session_with_segments(po2, cycle)
        print(f"Loaded {len(input_data)} segments for PROVE")

        print("Running PROVE tasks...")
        results = run_prove_with_ray(input_data)
        file_name = f"../metadata/po2_{po2}/lifted_receipts_po2_{po2}_cycle_{cycle}.json"
        with open(file_name, "w") as f:
            json.dump([json.loads(result.decode()) for result in results], f, indent=2)

        print(f"PROVE results saved to ../metadata/lifted_receipts.json ({len(results)} segments)")
        print(f"Elapsed time: {time.time() - start:.2f} seconds")

        return results
    elif task_type == TaskType.KECCAK:
        start = time.time()

        print("Starting KECCAK test...")

        print("Loading keccak request data...")
        keccak_requests = load_keccak_requests(po2, cycle)
        print(f"Loaded {len(keccak_requests)} keccak requests")

        print("Using Ray for distributed execution")
        results = run_keccak_with_ray(keccak_requests,po2, cycle)
        file_name = f"../metadata/po2_{po2}/keccak/keccak_receipts_po2_{po2}_cycle_{cycle}.json"
        with open(file_name, "w") as f:
            json.dump([json.loads(result.decode()) for result in results], f, indent=2)

        print("KECCAK test completed successfully")
        print(f"Elapsed time: {time.time() - start:.2f} seconds")

        return results
    elif task_type == TaskType.UNION:
        start = time.time()

        print("Starting UNION test...")

        print("Loading keccak receipt data...")
        keccak_receipts = load_keccak_receipts(po2, cycle)
        print(f"Loaded {len(keccak_receipts)} keccak receipts")

        if len(keccak_receipts) == 0:
            raise RuntimeError("No keccak receipts found")

        print("Using Ray for distributed UNION execution")
        result = run_union_with_ray(keccak_receipts, po2, cycle)
        file_name = f"../metadata/po2_{po2}/keccak/unioned_receipts_po2_{po2}_cycle_{cycle}.json"
        with open(file_name, "wb") as f:
            f.write(result)

        print("UNION test completed successfully")
        print(f"Elapsed time: {time.time() - start:.2f} seconds")
        return result
    elif task_type == TaskType.RESOLVE:
        start = time.time()

        print("Starting RESOLVE test...")
        result = run_resolve_with_ray(po2, cycle)
        file_name = f"../metadata/po2_{po2}/resolved_receipt_po2_{po2}_cycle_{cycle}.json"
        with open(file_name, "wb") as f:
            f.write(result)

        print("RESOLVE test completed successfully")
        print(f"Elapsed time: {time.time() - start:.2f} seconds")
        return result
    elif task_type == TaskType.FINALIZE:
        start = time.time()

        print("Starting FINALIZE test...")
        result = run_finalize_with_ray(po2, cycle)
        file_name = f"../metadata/po2_{po2}/result/finalized_receipt_po2_{po2}_cycle_{cycle}.json"
        with open(file_name, "wb") as f:
            f.write(result)

        print("FINALIZE test completed successfully")
        print(f"Elapsed time: {time.time() - start:.2f} seconds")
        return result
    elif task_type == TaskType.SNARK:
        start = time.time()

        print("Starting SNARK test...")
        result = run_snark_with_ray(po2, cycle)
        print("SNARK test completed successfully")
        print(f"Elapsed time: {time.time() - start:.2f} seconds")
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
    po2 = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    cycle = int(sys.argv[3]) if len(sys.argv) > 3 else 1

    print(f"Starting orchestrator for task {raw_arg} on PO2 {po2} cycle {cycle}")
    try:
        task_type = TaskType(raw_arg.upper())
    except ValueError:
        print(f"Invalid task type: {raw_arg}. Must be one of {[t.value for t in TaskType]}")
        sys.exit(1)

    try:
        result = main(task_type, po2, cycle)
        print(f"Task {task_type.value} completed successfully")

    except Exception as e:
        print(f"Task {task_type.value} failed: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)

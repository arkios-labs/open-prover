import json
import sys

import ray
import platform
from common.types import TaskType
from loader import load_lifted_receipts, load_session_with_segments, load_keccak_requests, load_keccak_receipts
from runner import run_join_with_ray, run_prove_with_ray, run_keccak_with_ray, run_union_with_ray, \
    run_resolve_with_ray, run_finalize_with_ray


def main(task_type: TaskType):
    if task_type == TaskType.JOIN:
        input_data = load_lifted_receipts()
        result = run_join_with_ray(input_data)
        with open("../metadata/root_receipt.json", "wb") as f:
            f.write(result)
        print("JOIN result saved to ../metadata/root_receipt.json")
        return result
    elif task_type == TaskType.PROVE:
        print("Loading segment data...")
        input_data = load_session_with_segments()
        print(f"Loaded {len(input_data)} segments for PROVE")

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

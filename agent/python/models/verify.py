from typing import List
import json


def verify_keccak_data(keccak_requests: List[bytes]) -> bool:
    """Verify that keccak request data is valid."""
    print(f"Verifying {len(keccak_requests)} keccak requests...")

    for i, keccak_bytes in enumerate(keccak_requests):
        try:
            keccak_json = keccak_bytes.decode()
            keccak_data = json.loads(keccak_json)

            required_fields = ['claim_digest', 'po2', 'control_root', 'input']
            for field in required_fields:
                if field not in keccak_data:
                    print(f"ERROR: Keccak request {i} missing required field '{field}'")
                    return False

            claim_digest = keccak_data['claim_digest']
            control_root = keccak_data['control_root']
            input_data = keccak_data['input']

            if not isinstance(claim_digest, list) or not all(isinstance(x, int) for x in claim_digest):
                print(f"ERROR: Keccak request {i} claim_digest must be a list of integers")
                return False

            if not isinstance(control_root, list) or not all(isinstance(x, int) for x in control_root):
                print(f"ERROR: Keccak request {i} control_root must be a list of integers")
                return False

            if not isinstance(input_data, list):
                print(f"ERROR: Keccak request {i} input must be a list")
                return False

            for j, state in enumerate(input_data):
                if not isinstance(state, list):
                    print(f"ERROR: Keccak request {i}, state {j} must be a list")
                    return False

                if len(state) != 25:
                    print(f"ERROR: Keccak request {i}, state {j} must have exactly 25 elements")
                    return False

                if not all(isinstance(x, int) for x in state):
                    print(f"ERROR: Keccak request {i}, state {j} must contain only integers")
                    return False

            if not isinstance(keccak_data['po2'], int):
                print(f"ERROR: Keccak request {i} po2 must be integer")
                return False

            print(f"Keccak request {i} validation passed (size: {len(keccak_bytes)} bytes)")

        except Exception as e:
            print(f"ERROR: Keccak request {i} validation failed: {e}")
            return False

    return True


def verify_segment_data(segments_data: List[bytes]) -> bool:
    """Verify that segment data is valid."""
    print(f"Verifying {len(segments_data)} segments...")

    for i, segment_bytes in enumerate(segments_data):
        try:
            segment_json = segment_bytes.decode()
            segment_data = json.loads(segment_json)

            required_fields = ['index', 'inner']
            for field in required_fields:
                if field not in segment_data:
                    print(f"ERROR: Segment {i} missing required field '{field}'")
                    return False

            inner = segment_data['inner']
            inner_fields = ['partial_image', 'claim', 'read_record', 'write_record']
            for field in inner_fields:
                if field not in inner:
                    print(f"ERROR: Segment {i} inner missing required field '{field}'")
                    return False

            print(f"Segment {i} validation passed (size: {len(segment_bytes)} bytes)")

        except Exception as e:
            print(f"ERROR: Segment {i} validation failed: {e}")
            return False

    return True
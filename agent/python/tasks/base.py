from abc import ABC, abstractmethod
from typing import List, Dict, Any
import subprocess
import os
import json


class TaskHandler(ABC):
    """
    Abstract base class for all task types like JOIN, PROVE, etc.
    Each subclass must implement the `run` method.
    """

    @abstractmethod
    def run(self, inputs: List[bytes]) -> bytes:
        """
        Execute the task using the given input byte streams.

        Args:
            inputs (List[bytes]): A list of serialized input bytes.

        Returns:
            bytes: The serialized output from the subprocess call
        """
        pass

    def _call_rust_binary(self, task_type: str, inputs: List[bytes]) -> bytes:
        """
        Helper method to call the Rust binary with the given task type and inputs.
        
        Args:
            task_type (str): The type of task to execute
            inputs (List[bytes]): Input data for the task
            
        Returns:
            bytes: Output from the Rust binary
        """
        # Debug: Print input information
        print(f"Task: {task_type}")
        print(f"Input count: {len(inputs)}")
        print(f"Input sizes: {[len(inp) for inp in inputs]}")

        if task_type == "PROVE":
            if len(inputs) != 1:
                raise ValueError(f"PROVE task expects exactly 1 input, got {len(inputs)}")
            input_data = inputs[0]
            print(f"PROVE input data size: {len(input_data)} bytes")
            print(f"PROVE input data preview: {input_data[:50]}...")
        elif task_type == "KECCAK":
            if len(inputs) != 1:
                raise ValueError(f"KECCAK task expects exactly 1 input, got {len(inputs)}")
            input_data = inputs[0]
            print(f"KECCAK input data size: {len(input_data)} bytes")
            print(f"KECCAK input data preview: {input_data[:200]}...")
        elif task_type == "RESOLVE":
            if len(inputs) != 1:
                raise ValueError(f"RESOLVE task expects exactly 1 input, got {len(inputs)}")
            input_data = inputs[0]
            print(f"RESOLVE input data size: {len(input_data)} bytes")
            print(f"RESOLVE input data preview: {input_data[:200]}...")
        elif task_type == "FINALIZE":
            if len(inputs) != 1:
                raise ValueError(f"FINALIZE task expects exactly 1 input, got {len(inputs)}")
            input_data = inputs[0]
            print(f"FINALIZE input data size: {len(input_data)} bytes")
            print(f"FINALIZE input data preview: {input_data[:200]}...")
        else:
            input_json = json.dumps([list(input) for input in inputs])
            input_data = input_json.encode()
            print(f"Input JSON length: {len(input_data)}")
            print(f"Input JSON preview: {input_data[:200]}...")

        env = os.environ.copy()
        env["AGENT_TYPE"] = "r0"
        env["TASK_TYPE"] = task_type

        try:
            result = subprocess.run(
                ["../r0_prover"],
                input=input_data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                check=True,
                timeout=300  # 5 minutes timeout
            )

            print(f"Rust binary stdout length: {len(result.stdout)}")
            print(f"Rust binary stderr length: {len(result.stderr)}")

            if result.stderr:
                print(f"Rust binary stderr: {result.stderr.decode()}")

            return result.stdout

        except subprocess.CalledProcessError as e:
            print(f"Rust binary failed with exit code {e.returncode}")
            print(f"Rust binary stdout: {e.stdout.decode() if e.stdout else 'None'}")
            print(f"Rust binary stderr: {e.stderr.decode() if e.stderr else 'None'}")
            raise
        except subprocess.TimeoutExpired as e:
            print(f"Rust binary timed out after {e.timeout} seconds")
            raise
        except FileNotFoundError:
            print("Rust binary '../r0_prover' not found")
            print("Current working directory:", os.getcwd())
            print("Available files:", os.listdir("."))
            raise

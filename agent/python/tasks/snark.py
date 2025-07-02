import os
import tempfile
import asyncio
from typing import List
from .base import TaskHandler
from pathlib import Path
import platform
import json

APP_DIR = ""
WITNESS_FILE = "output.wtns"
PROOF_FILE = "proof.json"
IDENT_FILE = "ident.json"
STARK_VERIFY_BIN = "stark_verify"
PROVER_BIN = "prover"

class SnarkTask(TaskHandler):
    """Task handler for SNARK operations with FIFO communication."""

    def run(self, inputs: List[bytes]) -> bytes:
        """
        Execute SNARK operation on rollup receipt data using FIFO communication.
        
        Args:
            inputs (List[bytes]): Rollup receipt data
            
        Returns:
            bytes: The SNARK receipt
        """
        assert len(inputs) == 1, "SNARK task expects exactly one input"
        return asyncio.run(self._run_async(inputs[0]))

    async def _run_async(self, stark_receipt_bytes: bytes) -> bytes:
        """
        Async implementation of SNARK operation using two-step process.
        
        Args:
            stark_receipt_bytes (bytes): STARK receipt data
            
        Returns:
            bytes: The SNARK receipt
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            work_dir = Path(tmpdir)
            arch = platform.machine().lower()

            if arch == "arm64":
                app_path = Path("../")
            else:
                app_path = Path("/home/ubuntu/snark")

            print(f"Working directory: {work_dir}")
            print(f"App path: {app_path.resolve()}")
            
            # 1. prepare_snark 호출: seal 파일 생성 및 receipt 정보 받기
            print("Step 1: Calling prepare_snark...")
            prepare_result_bytes = self._call_rust_binary("PREPARE_SNARK", [stark_receipt_bytes])
            
            if not prepare_result_bytes:
                raise ValueError("prepare_snark returned empty result")
            
            # prepare_snark 결과 파싱
            prepare_result_str = prepare_result_bytes.decode('utf-8')
            prepare_result = json.loads(prepare_result_str)
            
            seal_path = Path(prepare_result["seal_path"])
            receipt_claim = prepare_result["receipt_claim"]
            journal_bytes = prepare_result["journal_bytes"]
            
            print(f"Seal file path: {seal_path}")
            print(f"Receipt claim: {receipt_claim}")
            print(f"Journal bytes length: {len(journal_bytes)}")
            
            if not seal_path.exists():
                raise FileNotFoundError(f"Seal file not found: {seal_path}")
            
            # 2. stark_verify와 prover 실행
            witness_file = work_dir / WITNESS_FILE
            proof_file = work_dir / PROOF_FILE
            
            if witness_file.exists():
                os.remove(witness_file)
            
            os.mkfifo(witness_file, 0o700)
            print(f"Created witness FIFO: {witness_file}")
            
            # stark_verify 프로세스 시작
            print("Starting stark_verify process...")
            stark_verify_binary = app_path / STARK_VERIFY_BIN
            if not stark_verify_binary.exists():
                raise FileNotFoundError(f"stark_verify binary not found: {stark_verify_binary}")
            
            if not os.access(stark_verify_binary, os.X_OK):
                print(f"Setting execute permission for {stark_verify_binary}")
                os.chmod(stark_verify_binary, 0o755)
            
            wit_gen = await asyncio.create_subprocess_exec(
                str(stark_verify_binary),
                str(seal_path),
                str(witness_file),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # gnark prover 프로세스 시작
            print("Starting gnark prover process...")
            cs_file = app_path / "stark_verify.cs"
            pk_file = app_path / "stark_verify_final.pk.dmp"
            
            if not cs_file.exists():
                raise FileNotFoundError(f"Circuit file not found: {cs_file}")
            if not pk_file.exists():
                raise FileNotFoundError(f"Proving key file not found: {pk_file}")
            
            prover_binary = app_path / PROVER_BIN
            if not prover_binary.exists():
                raise FileNotFoundError(f"prover binary not found: {prover_binary}")
            
            if not os.access(prover_binary, os.X_OK):
                print(f"Setting execute permission for {prover_binary}")
                os.chmod(prover_binary, 0o755)
            
            prover = await asyncio.create_subprocess_exec(
                str(prover_binary),
                str(cs_file),
                str(pk_file),
                str(witness_file),
                str(proof_file),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )


            # stark_verify 완료 대기
            print("Waiting for stark_verify to complete...")
            wit_status = await wit_gen.wait()
            if wit_status != 0:
                stdout, stderr = await wit_gen.communicate()
                print(f"stark_verify stdout: {stdout.decode()}")
                print(f"stark_verify stderr: {stderr.decode()}")
                prover.kill()
                await prover.wait()
                raise RuntimeError(f"stark_verify failed with status {wit_status}")
            
            print("stark_verify completed successfully")
            
            # gnark prover 완료 대기
            print("Waiting for gnark prover to complete...")
            prover_status = await prover.wait()
            if prover_status != 0:
                stdout, stderr = await prover.communicate()
                print(f"prover stdout: {stdout.decode()}")
                print(f"prover stderr: {stderr.decode()}")
                raise RuntimeError(f"gnark prover failed with status {prover_status}")
            
            print("gnark prover completed successfully")
            
            # 3. proof 파일 확인 및 읽기
            if not proof_file.exists():
                raise FileNotFoundError(f"Proof file not found: {proof_file}")
            
            proof_bytes = proof_file.read_bytes()
            if not proof_bytes:
                raise ValueError("Proof file is empty")
            
            print(f"Proof file size: {len(proof_bytes)} bytes")
            
            # 4. get_snark_receipt 호출: proof 내용과 receipt 정보를 전달하여 SNARK receipt 생성
            print("Step 2: Calling get_snark_receipt...")

            snark_receipt_bytes = self._call_rust_binary("GET_SNARK_RECEIPT", [receipt_claim, journal_bytes, proof_bytes])
            
            if not snark_receipt_bytes:
                raise ValueError("get_snark_receipt returned empty result")
            
            print(f"SNARK receipt size: {len(snark_receipt_bytes)} bytes")
            print("SNARK operation completed successfully")
            
            return snark_receipt_bytes

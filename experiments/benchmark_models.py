"""
ORACLE Hardware & Model Benchmarking Harness (Brick 1)
Empirically evaluates local Ollama models on the target Intel Core i5 machine.
Measures:
  1. Inference latency (tokens/sec)
  2. Memory RSS footprint & RAM delta
  3. Pydantic JSON schema adherence rate
  4. Embedding speed & dimensionality
"""

import sys
import os
import time
from typing import List, Optional
import psutil
from pydantic import BaseModel, Field, field_validator

# Ensure project root is in path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from backend.inference.ollama_provider import OllamaProvider
from backend.inference.base import SchemaValidationError


# --- Benchmark Domain Schemas ---

class SystemDependency(BaseModel):
    source: str = Field(description="Name of dependent system or service")
    target: str = Field(description="Target dependency required")
    reason: str = Field(description="Why this dependency is required")


class SituationExtraction(BaseModel):
    entities: List[str] = Field(description="List of detected infrastructure or code entities")
    dependencies: List[SystemDependency] = Field(description="Discovered dependencies")
    primary_risk: str = Field(description="Primary operational risk identified")
    severity: str = Field(description="Risk severity: Low, Medium, High, or Critical")
    deadline_date: Optional[str] = Field(default=None, description="Any hard deadline mentioned")
    confidence: float = Field(description="Confidence score (e.g. 0.9 or 90)")

    @field_validator("confidence", mode="before")
    @classmethod
    def normalize_confidence(cls, v):
        """Defensive normalizer: converts percentage (0-100) to decimal (0.0-1.0)."""
        if isinstance(v, (int, float)) and v > 1.0 and v <= 100.0:
            return round(v / 100.0, 2)
        return v


# --- Benchmark Runner ---

SAMPLE_OPERATIONAL_CORPUS = (
    "Production Incident Report & Migration Note: "
    "Payment Gateway upgrade to v2 is blocked by the Redis cluster. "
    "Current Redis v5 cluster does not support mutual TLS 1.3 which is required by the new compliance standard. "
    "If the Redis cluster is not upgraded to v7.2 before October 15, the Payment Gateway will drop all EU transaction "
    "handshakes, leading to immediate checkout failures across European storefronts. "
    "Database DBA team (Sarah L.) has not approved the Redis downtime window yet."
)


def get_system_ram_mb() -> float:
    """Return total used system RAM in Megabytes."""
    return psutil.virtual_memory().used / (1024 * 1024)


def run_benchmark():
    print("=" * 80)
    print("          ORACLE HARDWARE & MODEL BENCHMARK HARNESS (BRICK 1)")
    print("=" * 80)

    provider = OllamaProvider()

    # 1. Health & Connection Check
    print("\n[1/4] Checking Ollama Daemon Health...")
    is_healthy = provider.health_check()
    if not is_healthy:
        print("[-] ERROR: Cannot connect to Ollama daemon at http://localhost:11434.")
        print("    Please verify that Ollama is running.")
        sys.exit(1)
    print("[+] Ollama is healthy and responsive at http://localhost:11434")

    installed_models = provider.list_installed_models()
    print(f"[+] Installed models detected: {installed_models}")

    candidate_models = ["qwen2.5:3b", "phi3.5:latest"]
    results = []

    # 2. Benchmark LLM Candidates
    print("\n[2/4] Benchmarking LLM Candidates on Intel Core i5 CPU...")
    print("-" * 80)

    for model_name in candidate_models:
        matching = [m for m in installed_models if model_name in m]
        if not matching:
            print(f"[!] Warning: Model '{model_name}' not found in installed list. Skipping.")
            continue
        actual_model = matching[0]

        print(f"\n--> Profiling Model: {actual_model}")
        initial_ram = get_system_ram_mb()

        prompt = (
            f"Analyze the following operational incident note and extract all entities, dependencies, "
            f"risks, and deadlines into the required JSON schema:\n\n{SAMPLE_OPERATIONAL_CORPUS}"
        )

        t_start = time.perf_counter()
        schema_passed = False
        extracted_obj = None
        error_msg = None

        try:
            extracted_obj = provider.generate_structured(
                prompt=prompt,
                schema=SituationExtraction,
                model=actual_model,
                temperature=0.0,
            )
            schema_passed = True
        except SchemaValidationError as e:
            error_msg = f"Schema validation failed: {str(e)}"
        except Exception as e:
            error_msg = f"Inference error: {str(e)}"

        total_elapsed_sec = time.perf_counter() - t_start
        peak_ram = get_system_ram_mb()
        ram_delta_mb = max(0.0, peak_ram - initial_ram)

        # Raw speed probe to measure completion tokens/sec
        raw_res = provider.generate(
            prompt="Summarize the core bottleneck in 20 words: " + SAMPLE_OPERATIONAL_CORPUS,
            model=actual_model,
            temperature=0.0,
        )

        tokens_per_sec = raw_res.tokens_per_second
        tokens_generated = raw_res.completion_tokens

        results.append({
            "model": actual_model,
            "schema_passed": schema_passed,
            "latency_sec": round(total_elapsed_sec, 2),
            "tokens_per_sec": tokens_per_sec,
            "tokens_generated": tokens_generated,
            "ram_delta_mb": round(ram_delta_mb, 1),
            "extracted_obj": extracted_obj,
            "error_msg": error_msg,
        })

        print(f"    - Structured Extraction Latency: {total_elapsed_sec:.2f}s")
        print(f"    - Raw Generation Velocity:       {tokens_per_sec:.2f} tokens/sec")
        print(f"    - Schema Validation Pass:        {'PASSED [OK]' if schema_passed else 'FAILED [X]'}")
        if extracted_obj:
            print(f"    - Extracted Entities:            {extracted_obj.entities}")
            print(f"    - Primary Risk:                  {extracted_obj.primary_risk[:70]}...")
            print(f"    - Severity / Confidence:         {extracted_obj.severity} (Score: {extracted_obj.confidence})")
        elif error_msg:
            print(f"    - Failure Diagnostics:           {error_msg}")

    # 3. Benchmark Embedding Model
    print("\n[3/4] Benchmarking Embedding Model ('nomic-embed-text')...")
    print("-" * 80)
    embedding_models = [m for m in installed_models if "nomic-embed" in m]
    if embedding_models:
        emb_model = embedding_models[0]
        t_emb_start = time.perf_counter()
        emb_res = provider.embed(SAMPLE_OPERATIONAL_CORPUS, model=emb_model)
        emb_elapsed_ms = (time.perf_counter() - t_emb_start) * 1000.0

        print(f"    - Model Name:     {emb_model}")
        print(f"    - Vector Dims:    {emb_res.dimensions} dimensions")
        print(f"    - Single Latency: {emb_elapsed_ms:.2f} ms")
    else:
        print("[!] Warning: nomic-embed-text not found.")

    # 4. Final Architectural Summary
    print("\n" + "=" * 80)
    print("                 BENCHMARK ARCHITECTURAL EVALUATION MATRIX")
    print("=" * 80)
    print(f"{'Model':<24} | {'Schema Valid':<13} | {'Tokens/Sec':<12} | {'Latency (s)':<12} | {'Verdict'}")
    print("-" * 80)

    for r in results:
        status = "PASSED" if r["schema_passed"] else "FAILED"
        verdict = "RECOMMENDED" if r["schema_passed"] and r["tokens_per_sec"] >= 6.0 else "SUBOPTIMAL"
        print(f"{r['model']:<24} | {status:<13} | {r['tokens_per_sec']:<12.1f} | {r['latency_sec']:<12.2f} | {verdict}")

    print("=" * 80)
    print("Benchmark complete.\n")


if __name__ == "__main__":
    run_benchmark()

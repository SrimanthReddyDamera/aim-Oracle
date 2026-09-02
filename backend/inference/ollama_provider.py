"""
ORACLE Ollama Inference Provider
Implements production-grade connectivity, structured JSON schema enforcement,
telemetry capture, and automatic repair routines for the local Ollama daemon.
"""

import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple, Type, TypeVar
import httpx
from pydantic import BaseModel, ValidationError

from backend.core.config import settings
from backend.inference.base import (
    LLMProvider,
    LLMResponse,
    EmbeddingResponse,
    ModelGatewayError,
    ModelUnavailableError,
    InferenceTimeoutError,
    SchemaValidationError,
)

T = TypeVar("T", bound=BaseModel)


class OllamaProvider(LLMProvider):
    """
    Robust local provider connecting to Ollama via HTTP API.
    Features connection pooling, strict schema validation, and automatic repair.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        default_model: Optional[str] = None,
        embedding_model: Optional[str] = None,
        timeout: Optional[float] = None,
    ):
        self.base_url = (base_url or settings.ollama.base_url).rstrip("/")
        self.default_model = default_model or settings.ollama.default_model
        self.embedding_model = embedding_model or settings.ollama.embedding_model
        self.timeout = timeout or settings.ollama.timeout_seconds

        # Reusable client with connection pooling
        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=httpx.Timeout(self.timeout, connect=5.0),
        )

    def close(self):
        """Release underlying connection pool."""
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def health_check(self) -> bool:
        """Verify that the local Ollama instance is alive and responsive."""
        try:
            res = self._client.get("/api/tags")
            return res.status_code == 200
        except (httpx.ConnectError, httpx.TimeoutException):
            return False

    def list_installed_models(self) -> List[str]:
        """Retrieve names of all models currently available in local storage."""
        try:
            res = self._client.get("/api/tags")
            res.raise_for_status()
            data = res.json()
            return [m.get("name") for m in data.get("models", [])]
        except Exception as e:
            raise ModelUnavailableError(f"Failed to query Ollama models: {e}") from e

    def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
    ) -> LLMResponse:
        """Execute raw text generation against local Ollama."""
        target_model = model or self.default_model
        temp = temperature if temperature is not None else settings.ollama.temperature

        payload = {
            "model": target_model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temp,
            },
        }
        if system:
            payload["system"] = system

        t0 = time.perf_counter()
        try:
            res = self._client.post("/api/generate", json=payload)
            res.raise_for_status()
        except httpx.ConnectError as e:
            raise ModelUnavailableError(f"Cannot connect to Ollama at {self.base_url}: {e}") from e
        except httpx.TimeoutException as e:
            raise InferenceTimeoutError(f"Ollama generation timed out after {self.timeout}s: {e}") from e
        except httpx.HTTPStatusError as e:
            raise ModelGatewayError(f"Ollama returned HTTP error {e.response.status_code}: {e.response.text}") from e

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        data = res.json()

        content = data.get("response", "")
        eval_count = data.get("eval_count", 0)
        prompt_eval_count = data.get("prompt_eval_count", 0)
        
        # Calculate tokens per second from Ollama telemetry
        eval_duration_ns = data.get("eval_duration", 0)
        if eval_duration_ns > 0 and eval_count > 0:
            tokens_per_sec = (eval_count / (eval_duration_ns / 1e9))
        elif elapsed_ms > 0 and eval_count > 0:
            tokens_per_sec = eval_count / (elapsed_ms / 1000.0)
        else:
            tokens_per_sec = 0.0

        return LLMResponse(
            content=content,
            model_name=target_model,
            prompt_tokens=prompt_eval_count,
            completion_tokens=eval_count,
            total_duration_ms=round(elapsed_ms, 2),
            tokens_per_second=round(tokens_per_sec, 2),
        )

    def generate_structured(
        self,
        prompt: str,
        schema: Type[T],
        system: Optional[str] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
    ) -> T:
        """
        Generate structured output strictly validated against a Pydantic schema.
        Utilizes Ollama's native JSON schema constraints and applies a single-pass repair fallback.
        """
        target_model = model or self.default_model
        temp = temperature if temperature is not None else settings.ollama.temperature
        json_schema = schema.model_json_schema()

        # System prompt instructing strict JSON schema adherence
        system_instructions = (
            f"{system}\n" if system else ""
        ) + (
            "You are a strict, deterministic structured reasoning engine. "
            "You must output ONLY a valid JSON object matching the provided JSON schema. "
            "Do not include any conversational filler, markdown codeblocks, or extra text."
        )

        payload = {
            "model": target_model,
            "prompt": prompt,
            "system": system_instructions,
            "format": json_schema,
            "stream": False,
            "options": {
                "temperature": temp,
            },
        }

        try:
            res = self._client.post("/api/generate", json=payload)
            res.raise_for_status()
            data = res.json()
            raw_text = data.get("response", "").strip()
        except httpx.ConnectError as e:
            raise ModelUnavailableError(f"Cannot connect to Ollama at {self.base_url}: {e}") from e
        except httpx.TimeoutException as e:
            raise InferenceTimeoutError(f"Ollama generation timed out after {self.timeout}s: {e}") from e
        except Exception as e:
            raise ModelGatewayError(f"Failed to execute structured generation: {e}") from e

        # 1. Attempt direct Pydantic validation
        parsed_obj, val_err = self._clean_and_validate(raw_text, schema)
        if parsed_obj is not None:
            return parsed_obj

        # 2. Validation Failed: Execute Single-Pass Repair Routine
        repaired_obj = self._attempt_schema_repair(
            model=target_model,
            broken_output=raw_text,
            validation_error=val_err or "Unknown validation error",
            schema=schema,
            json_schema=json_schema,
        )
        if repaired_obj is not None:
            return repaired_obj

        raise SchemaValidationError(
            message=f"Model '{target_model}' failed to produce valid JSON adhering to {schema.__name__}. Error: {val_err}",
            raw_output=raw_text,
            schema_name=schema.__name__,
        )

    def _clean_and_validate(self, text: str, schema: Type[T]) -> Tuple[Optional[T], Optional[str]]:
        """Strip markdown wrappers if present and validate against Pydantic schema."""
        cleaned = text.strip()
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
            cleaned = re.sub(r"\s*```$", "", cleaned)
            cleaned = cleaned.strip()

        try:
            return schema.model_validate_json(cleaned), None
        except Exception as e:
            return None, str(e)

    def _attempt_schema_repair(
        self,
        model: str,
        broken_output: str,
        validation_error: str,
        schema: Type[T],
        json_schema: Dict[str, Any],
    ) -> Optional[T]:
        """Single-pass targeted repair prompt when initial output has formatting errors."""
        repair_prompt = (
            f"The previous output failed validation against this JSON Schema:\n"
            f"ValidationError: {validation_error}\n\n"
            f"Schema:\n"
            f"{json.dumps(json_schema, indent=2)}\n\n"
            f"Broken Output:\n"
            f"{broken_output}\n\n"
            f"Fix the error and output ONLY the corrected JSON object:"
        )

        try:
            res = self._client.post(
                "/api/generate",
                json={
                    "model": model,
                    "prompt": repair_prompt,
                    "format": json_schema,
                    "stream": False,
                    "options": {"temperature": 0.0},
                },
            )
            res.raise_for_status()
            repaired_text = res.json().get("response", "").strip()
            obj, _ = self._clean_and_validate(repaired_text, schema)
            return obj
        except Exception:
            return None

    def embed(
        self,
        text: str,
        model: Optional[str] = None,
    ) -> EmbeddingResponse:
        """Generate vector embedding for text using Ollama."""
        target_model = model or self.embedding_model
        t0 = time.perf_counter()

        try:
            res = self._client.post(
                "/api/embed",
                json={
                    "model": target_model,
                    "input": text,
                },
            )
            if res.status_code == 404:
                res = self._client.post(
                    "/api/embeddings",
                    json={
                        "model": target_model,
                        "prompt": text,
                    },
                )
                res.raise_for_status()
                data = res.json()
                embedding = data.get("embedding", [])
            else:
                res.raise_for_status()
                data = res.json()
                embeddings = data.get("embeddings", [])
                embedding = embeddings[0] if embeddings else []

        except httpx.ConnectError as e:
            raise ModelUnavailableError(f"Cannot connect to Ollama at {self.base_url}: {e}") from e
        except Exception as e:
            raise ModelGatewayError(f"Failed to generate embedding: {e}") from e

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return EmbeddingResponse(
            embedding=embedding,
            dimensions=len(embedding),
            model_name=target_model,
            duration_ms=round(elapsed_ms, 2),
        )

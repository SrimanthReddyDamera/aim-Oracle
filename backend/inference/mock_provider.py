"""
ORACLE Mock Inference Provider
Provides deterministic, zero-latency responses for automated unit and integration tests.
"""

from typing import Any, Dict, List, Optional, Type, TypeVar
import json
from pydantic import BaseModel

from backend.inference.base import (
    LLMProvider,
    LLMResponse,
    EmbeddingResponse,
    SchemaValidationError,
)

T = TypeVar("T", bound=BaseModel)


class MockProvider(LLMProvider):
    """
    Deterministic mock provider for testing.
    Can be configured with canned responses, custom exceptions, or auto-generating schemas.
    """

    def __init__(self):
        self.canned_responses: List[str] = []
        self.canned_structured_data: Dict[str, Any] = {}
        self.call_history: List[Dict[str, Any]] = []
        self.should_fail_health: bool = False
        self.simulate_schema_error: bool = False

    def health_check(self) -> bool:
        return not self.should_fail_health

    def set_canned_text(self, text: str):
        """Queue a canned raw text response."""
        self.canned_responses.append(text)

    def set_canned_structured(self, schema_name: str, data: Dict[str, Any]):
        """Register mock data for a specific schema name."""
        self.canned_structured_data[schema_name] = data

    def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
    ) -> LLMResponse:
        self.call_history.append({
            "type": "generate",
            "prompt": prompt,
            "system": system,
            "model": model,
            "temperature": temperature,
        })

        content = self.canned_responses.pop(0) if self.canned_responses else "Mock response"
        return LLMResponse(
            content=content,
            model_name=model or "mock-model",
            prompt_tokens=len(prompt.split()),
            completion_tokens=len(content.split()),
            total_duration_ms=1.0,
            tokens_per_second=1000.0,
        )

    def generate_structured(
        self,
        prompt: str,
        schema: Type[T],
        system: Optional[str] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
    ) -> T:
        schema_name = schema.__name__
        self.call_history.append({
            "type": "generate_structured",
            "prompt": prompt,
            "schema": schema_name,
            "system": system,
            "model": model,
        })

        if self.simulate_schema_error:
            raise SchemaValidationError(
                message=f"Simulated schema validation error for {schema_name}",
                raw_output="{'invalid': 'json'}",
                schema_name=schema_name,
            )

        if schema_name in self.canned_structured_data:
            data = self.canned_structured_data[schema_name]
            return schema.model_validate(data)

        # Fallback: attempt to instantiate schema with empty / default values
        try:
            return schema.model_validate({})
        except Exception:
            # If default instantiation fails, construct minimal dummy object
            dummy_json = {}
            for field_name, field_info in schema.model_fields.items():
                if field_info.annotation is str:
                    dummy_json[field_name] = "mock_value"
                elif field_info.annotation is int:
                    dummy_json[field_name] = 1
                elif field_info.annotation is float:
                    dummy_json[field_name] = 1.0
                elif field_info.annotation is bool:
                    dummy_json[field_name] = True
                elif getattr(field_info.annotation, "__origin__", None) is list:
                    dummy_json[field_name] = []
                else:
                    dummy_json[field_name] = None
            return schema.model_validate(dummy_json)

    def embed(
        self,
        text: str,
        model: Optional[str] = None,
    ) -> EmbeddingResponse:
        self.call_history.append({
            "type": "embed",
            "text": text,
            "model": model,
        })
        # Deterministic 768-dim mock vector
        dim = 768
        val = (len(text) % 100) / 100.0
        return EmbeddingResponse(
            embedding=[val] * dim,
            dimensions=dim,
            model_name=model or "mock-embedding",
            duration_ms=0.5,
        )

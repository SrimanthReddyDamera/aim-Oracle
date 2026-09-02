"""
ORACLE Inference Gateway — Abstract Base Interfaces
Provides a clean, vendor-neutral abstraction layer for language model and embedding operations.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Type, TypeVar
from pydantic import BaseModel, Field

# Generic Type variable for Pydantic schema return types
T = TypeVar("T", bound=BaseModel)


# --- Typed Custom Exceptions ---

class ModelGatewayError(Exception):
    """Base exception for all Model Gateway operations."""
    pass


class ModelUnavailableError(ModelGatewayError):
    """Raised when the inference engine (e.g. Ollama service) is unreachable."""
    pass


class InferenceTimeoutError(ModelGatewayError):
    """Raised when model generation exceeds the configured hardware deadline."""
    pass


class SchemaValidationError(ModelGatewayError):
    """Raised when the model's output cannot be parsed or validated against the target Pydantic schema."""
    def __init__(self, message: str, raw_output: str, schema_name: str, original_error: Optional[Exception] = None):
        super().__init__(message)
        self.message = message
        self.raw_output = raw_output
        self.schema_name = schema_name
        self.original_error = original_error


# --- Telemetry & Response Containers ---

class LLMResponse(BaseModel):
    """Structured response object containing model text and hardware telemetry."""
    content: str = Field(description="Raw generated response string")
    parsed_json: Optional[Dict[str, Any]] = Field(default=None, description="Parsed JSON dictionary if applicable")
    model_name: str = Field(description="Identifier of the model that generated the response")
    prompt_tokens: int = Field(default=0, description="Number of tokens in the prompt")
    completion_tokens: int = Field(default=0, description="Number of tokens generated")
    total_duration_ms: float = Field(default=0.0, description="Total wall-clock generation time in milliseconds")
    tokens_per_second: float = Field(default=0.0, description="Generation velocity on the target hardware")


class EmbeddingResponse(BaseModel):
    """Container for vector embedding outputs."""
    embedding: List[float] = Field(description="Dense vector representation")
    dimensions: int = Field(description="Dimensionality of the vector")
    model_name: str = Field(description="Model used for generating the embedding")
    duration_ms: float = Field(default=0.0, description="Embedding calculation time in milliseconds")


# --- Abstract Gateway Provider ---

class LLMProvider(ABC):
    """
    Abstract interface for model providers.
    All inference engines (Ollama, Mock, future cloud APIs) must conform to this contract.
    """

    @abstractmethod
    def health_check(self) -> bool:
        """Verify that the underlying inference engine is active and reachable."""
        pass

    @abstractmethod
    def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
    ) -> LLMResponse:
        """Execute raw text generation."""
        pass

    @abstractmethod
    def generate_structured(
        self,
        prompt: str,
        schema: Type[T],
        system: Optional[str] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
    ) -> T:
        """
        Generate structured output guaranteed to conform to the specified Pydantic schema.
        Must handle schema extraction, validation, and single-pass repair if needed.
        """
        pass

    @abstractmethod
    def embed(
        self,
        text: str,
        model: Optional[str] = None,
    ) -> EmbeddingResponse:
        """Generate vector embedding for the input text."""
        pass

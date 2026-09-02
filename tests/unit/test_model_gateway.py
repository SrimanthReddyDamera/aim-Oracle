"""
Unit Tests for ORACLE Model Gateway (Brick 1)
Tests abstract interfaces, schema validation, error recovery, and provider decoupling.
"""

import pytest
from typing import List, Optional
from pydantic import BaseModel, Field

from backend.inference.base import (
    LLMProvider,
    LLMResponse,
    EmbeddingResponse,
    SchemaValidationError,
    ModelUnavailableError,
)
from backend.inference.mock_provider import MockProvider
from backend.inference.ollama_provider import OllamaProvider


# Sample Test Schemas
class RiskAssessment(BaseModel):
    risk_id: str = Field(description="Unique risk identifier")
    severity: str = Field(description="Low, Medium, High, or Critical")
    description: str = Field(description="Detailed explanation")
    mitigation_steps: List[str] = Field(default_factory=list)


class SystemEntity(BaseModel):
    name: str
    entity_type: str
    is_critical: bool


# --- Test Suite ---

def test_mock_provider_health():
    """Verify mock provider responds to health check status toggles."""
    provider = MockProvider()
    assert provider.health_check() is True

    provider.should_fail_health = True
    assert provider.health_check() is False


def test_mock_provider_generate():
    """Verify raw text generation and call history tracking."""
    provider = MockProvider()
    provider.set_canned_text("System readiness verified: OK")

    res = provider.generate("Check system status")
    assert isinstance(res, LLMResponse)
    assert res.content == "System readiness verified: OK"
    assert res.model_name == "mock-model"
    assert len(provider.call_history) == 1
    assert provider.call_history[0]["prompt"] == "Check system status"


def test_mock_provider_structured_output():
    """Verify structured generation validates directly against Pydantic schema."""
    provider = MockProvider()
    provider.set_canned_structured("RiskAssessment", {
        "risk_id": "RISK-101",
        "severity": "Critical",
        "description": "Database lock contention during migration",
        "mitigation_steps": ["Add timeout", "Batch update"]
    })

    result = provider.generate_structured("Analyze migration risk", RiskAssessment)
    assert isinstance(result, RiskAssessment)
    assert result.risk_id == "RISK-101"
    assert result.severity == "Critical"
    assert len(result.mitigation_steps) == 2


def test_mock_provider_schema_error_simulation():
    """Verify SchemaValidationError is cleanly raised when triggered."""
    provider = MockProvider()
    provider.simulate_schema_error = True

    with pytest.raises(SchemaValidationError) as exc_info:
        provider.generate_structured("Test prompt", RiskAssessment)

    assert "RiskAssessment" in exc_info.value.schema_name
    assert exc_info.value.message is not None


def test_mock_provider_embedding():
    """Verify vector embedding generation returns correct dimensions."""
    provider = MockProvider()
    res = provider.embed("Sample operational procedure document")
    assert isinstance(res, EmbeddingResponse)
    assert res.dimensions == 768
    assert len(res.embedding) == 768


def test_ollama_clean_and_validate_markdown_stripping():
    """Verify markdown code blocks are safely stripped before Pydantic parsing."""
    provider = OllamaProvider(base_url="http://127.0.0.1:11434")

    # 1. Clean JSON
    clean_json = '{"name": "AuthService", "entity_type": "service", "is_critical": true}'
    parsed, err = provider._clean_and_validate(clean_json, SystemEntity)
    assert parsed is not None
    assert err is None
    assert parsed.name == "AuthService"
    assert parsed.is_critical is True

    # 2. Markdown wrapped JSON
    wrapped_json = '```json\n{"name": "PostgresDB", "entity_type": "database", "is_critical": true}\n```'
    parsed_wrapped, err = provider._clean_and_validate(wrapped_json, SystemEntity)
    assert parsed_wrapped is not None
    assert err is None
    assert parsed_wrapped.name == "PostgresDB"

    # 3. Invalid JSON structure
    broken_json = '{"name": "Broken", "missing_closing_brace":'
    parsed_broken, err = provider._clean_and_validate(broken_json, SystemEntity)
    assert parsed_broken is None
    assert err is not None


def test_provider_decoupling():
    """Verify that domain logic accepting LLMProvider is fully agnostic of the concrete implementation."""
    def domain_task(provider: LLMProvider) -> str:
        res = provider.generate("Domain prompt")
        return res.content

    mock = MockProvider()
    mock.set_canned_text("Decoupled execution works")
    assert domain_task(mock) == "Decoupled execution works"

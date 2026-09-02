"""
ORACLE Configuration Module
Defines global settings, hardware constraints, and provider connection parameters.
"""

import os
from pydantic import BaseModel, Field


class OllamaSettings(BaseModel):
    """Connection and model parameters for the local Ollama instance."""
    base_url: str = Field(
        default=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
        description="Base URL for the Ollama REST API"
    )
    default_model: str = Field(
        default=os.getenv("ORACLE_DEFAULT_MODEL", "qwen2.5:3b"),
        description="Default LLM for structured reasoning and extraction"
    )
    embedding_model: str = Field(
        default=os.getenv("ORACLE_EMBEDDING_MODEL", "nomic-embed-text:latest"),
        description="Default embedding model for vector representations"
    )
    timeout_seconds: float = Field(
        default=90.0,
        description="HTTP request timeout in seconds (CPU inference safe)"
    )
    max_retries: int = Field(
        default=2,
        description="Maximum retries for network/schema repair failures"
    )
    temperature: float = Field(
        default=0.1,
        description="Sampling temperature for deterministic structured output"
    )


class Settings(BaseModel):
    """Master application settings container."""
    app_name: str = "ORACLE"
    version: str = "0.1.0"
    ollama: OllamaSettings = Field(default_factory=OllamaSettings)


# Singleton global settings instance
settings = Settings()

"""
ORACLE Adapter Configuration Models (Brick 3.9)
Configuration and authentication abstractions for remote enterprise datastores.
Enforces zero hardcoded credentials, URLs, projects, or repository names.
"""

import os
from typing import List, Optional
from dotenv import load_dotenv
from pydantic import BaseModel, Field

load_dotenv()


class JiraConfig(BaseModel):
    """Configuration container for Jira REST API provider."""
    base_url: str = Field(description="Base URL of Jira instance (e.g. https://company.atlassian.net)")
    email_or_username: Optional[str] = Field(default=None, description="Username or email for Basic Auth")
    api_token: Optional[str] = Field(default=None, repr=False, description="Jira API token or Personal Access Token")
    project_keys: List[str] = Field(default_factory=list, description="Optional project key filters (e.g. ['PROJ', 'ENG'])")
    timeout_seconds: float = Field(default=2.5, ge=0.1, le=30.0, description="HTTP socket and connect timeout ceiling")
    max_retries: int = Field(default=2, ge=0, le=5, description="Maximum retry attempts on transient network or 429 errors")
    page_size: int = Field(default=20, ge=1, le=100, description="Page size for JQL issue search pagination")
    rate_limit_backoff_factor: float = Field(default=1.0, ge=0.1, description="Backoff multiplier on rate-limited responses")

    def __repr__(self) -> str:
        token_disp = "***REDACTED***" if self.api_token else "None"
        return (
            f"JiraConfig(base_url={self.base_url!r}, email={self.email_or_username!r}, "
            f"api_token={token_disp}, projects={self.project_keys!r})"
        )

    @classmethod
    def from_env(cls) -> "JiraConfig":
        """Instantiate JiraConfig from environment variables (.env)."""
        load_dotenv()
        base_url = os.getenv("JIRA_BASE_URL", "https://your-domain.atlassian.net")
        email = os.getenv("JIRA_EMAIL") or os.getenv("JIRA_USERNAME")
        api_token = os.getenv("JIRA_API_TOKEN")
        projects_str = os.getenv("JIRA_PROJECTS", "")
        project_keys = [p.strip() for p in projects_str.split(",") if p.strip()]
        return cls(
            base_url=base_url,
            email_or_username=email,
            api_token=api_token,
            project_keys=project_keys,
        )


class GitHubConfig(BaseModel):
    """Configuration container for GitHub Search API provider."""
    base_url: str = Field(default="https://api.github.com", description="Base URL of GitHub API (e.g. https://api.github.com or GHE endpoint)")
    api_token: Optional[str] = Field(default=None, repr=False, description="Personal Access Token or GitHub App Token for authorization")
    repos: List[str] = Field(default_factory=list, description="Optional target repository filters (e.g. ['org/repo-a', 'org/repo-b'])")
    timeout_seconds: float = Field(default=2.5, ge=0.1, le=30.0, description="HTTP socket and connect timeout ceiling")
    max_retries: int = Field(default=2, ge=0, le=5, description="Maximum retry attempts on transient network or rate-limit errors")
    per_page: int = Field(default=20, ge=1, le=100, description="Results per page for GitHub Search API")
    rate_limit_backoff_factor: float = Field(default=1.0, ge=0.1, description="Backoff multiplier on rate-limited responses")

    def __repr__(self) -> str:
        token_disp = "***REDACTED***" if self.api_token else "None"
        return (
            f"GitHubConfig(base_url={self.base_url!r}, api_token={token_disp}, "
            f"repos={self.repos!r})"
        )

    @classmethod
    def from_env(cls) -> "GitHubConfig":
        """Instantiate GitHubConfig from environment variables (.env)."""
        load_dotenv()
        base_url = os.getenv("GITHUB_BASE_URL", "https://api.github.com")
        api_token = os.getenv("GITHUB_API_TOKEN") or os.getenv("GITHUB_TOKEN")
        repos_str = os.getenv("GITHUB_REPOS", "")
        repos = [r.strip() for r in repos_str.split(",") if r.strip()]
        return cls(
            base_url=base_url,
            api_token=api_token,
            repos=repos,
        )

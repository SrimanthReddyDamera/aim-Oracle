"""
ORACLE Jira EvidenceProvider Adapter (Brick 3.9)
Production-grade integration with Jira REST API (Cloud & Server/Data Center).
Implements authentication, JQL query synthesis, pagination, rate-limit backoff,
timeout isolation, and standardized Evidence normalization.
"""

import base64
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

from backend.evidence.models import Evidence
from backend.retrieval.adapters.config import JiraConfig
from backend.retrieval.base_external import ExternalEvidenceProvider
from backend.retrieval.provider import ProviderCapability


class JiraEvidenceProvider(ExternalEvidenceProvider):
    """
    EvidenceProvider adapter for Jira issue tracking systems.
    Translates natural language and entity queries into structured JQL,
    executing search across Jira Cloud / DC with rate-limit and circuit-breaker protections.
    """

    def __init__(self, config: JiraConfig, client: Optional[httpx.Client] = None):
        super().__init__(
            provider_id="jira",
            timeout_seconds=config.timeout_seconds,
            circuit_breaker_threshold=3,
        )
        self.config = config
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(config.timeout_seconds),
            headers=self._build_headers(),
        )

    def _build_headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "User-Agent": "ORACLE-Investigation-Engine/3.9",
        }
        if self.config.email_or_username and self.config.api_token:
            auth_str = f"{self.config.email_or_username}:{self.config.api_token}"
            b64_auth = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")
            headers["Authorization"] = f"Basic {b64_auth}"
        elif self.config.api_token:
            headers["Authorization"] = f"Bearer {self.config.api_token}"
        return headers

    @property
    def capabilities(self) -> Set[ProviderCapability]:
        return {
            ProviderCapability.LEXICAL_SEARCH,
            ProviderCapability.NETWORK_REMOTE,
            ProviderCapability.STRUCTURED_FILTER,
            ProviderCapability.ENTITY_LOOKUP,
        }

    def _sanitize_jql_text(self, query: str) -> str:
        """Sanitize free text for JQL query avoiding injection or syntax errors."""
        # Strip characters with special JQL meaning: + - & | ! ( ) { } [ ] ^ ~ * ? \ : ;
        cleaned = re.sub(r'[\+\-\&\|\!\(\)\{\}\[\]\^\~\*\?\\/\"\;:]', " ", query)
        tokens = [t for t in cleaned.split() if len(t) > 1]
        return " ".join(tokens)

    def _build_jql(self, query: str, filters: Optional[Dict[str, Any]] = None) -> str:
        """Constructs safe, structured JQL query from input text and optional filters."""
        clauses: List[str] = []

        # Scope to configured project keys if specified
        if self.config.project_keys:
            proj_list = ", ".join(f'"{p}"' for p in self.config.project_keys)
            clauses.append(f"project in ({proj_list})")

        # Check for direct issue key mention in query (e.g. PROJ-123)
        key_matches = re.findall(r"\b[A-Z][A-Z0-9]+-\d+\b", query)
        if key_matches:
            key_list = ", ".join(f'"{k}"' for k in key_matches)
            clauses.append(f"(key in ({key_list}) OR text ~ \"{self._sanitize_jql_text(query)}\")")
        else:
            sanitized = self._sanitize_jql_text(query)
            if sanitized:
                clauses.append(f'text ~ "{sanitized}"')

        # Structured filters (e.g. status, issue_type)
        if filters:
            if "status" in filters:
                clauses.append(f'status = "{filters["status"]}"')
            if "issue_type" in filters:
                clauses.append(f'issuetype = "{filters["issue_type"]}"')

        if not clauses:
            return "order by updated desc"
        return " AND ".join(clauses) + " order by updated desc"

    def search(
        self,
        query: str,
        k: int = 5,
        filters: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[Tuple[Evidence, float]], float]:
        t0 = time.perf_counter()
        if self.is_circuit_open():
            return [], (time.perf_counter() - t0) * 1000.0

        cached = self._get_cached_search(query, k, filters)
        if cached is not None:
            return cached

        jql = self._build_jql(query, filters=filters)
        base = self.config.base_url.rstrip("/")
        url = f"{base}/rest/api/3/search/jql"
        params = {
            "jql": jql,
            "maxResults": min(k, self.config.page_size),
            "fields": "summary,description,status,issuetype,priority,assignee,reporter,resolution,created,updated",
        }

        retries = 0
        while retries <= self.config.max_retries:
            try:
                response = self._client.get(url, params=params)
                if response.status_code in [404, 410] and "/rest/api/3/search/jql" in url:
                    # Fall back to Jira Server / DC v2 endpoint
                    url = f"{base}/rest/api/2/search"
                    continue

                if response.status_code == 429:
                    # Rate-limited
                    retry_after = float(response.headers.get("Retry-After", 1.0)) * self.config.rate_limit_backoff_factor
                    retries += 1
                    if retries <= self.config.max_retries:
                        time.sleep(min(retry_after, 2.0))
                        continue
                    else:
                        self.record_failure("RateLimit429")
                        return [], (time.perf_counter() - t0) * 1000.0

                if response.status_code >= 400:
                    self.record_failure(f"HTTP_{response.status_code}")
                    return [], (time.perf_counter() - t0) * 1000.0

                data = response.json()
                self.record_success()
                break
            except Exception as exc:
                retries += 1
                if retries > self.config.max_retries:
                    self.record_failure(type(exc).__name__)
                    return [], (time.perf_counter() - t0) * 1000.0
                time.sleep(0.2 * retries)

        issues = data.get("issues", [])
        evidence_list: List[Tuple[Evidence, float]] = []

        q_tokens = set(query.lower().split())

        for rank, issue in enumerate(issues, start=1):
            key = issue.get("key", "UNKNOWN")
            fields = issue.get("fields", {})
            summary = fields.get("summary") or ""
            desc = fields.get("description") or ""
            status_obj = fields.get("status") or {}
            status_name = status_obj.get("name") if isinstance(status_obj, dict) else str(status_obj)
            type_obj = fields.get("issuetype") or {}
            type_name = type_obj.get("name") if isinstance(type_obj, dict) else str(type_obj)
            priority_obj = fields.get("priority") or {}
            priority_name = priority_obj.get("name") if isinstance(priority_obj, dict) else str(priority_obj)

            content_lines = [
                f"Issue Key: {key}",
                f"Type: {type_name}",
                f"Status: {status_name}",
                f"Priority: {priority_name}",
                f"Summary: {summary}",
            ]
            if desc:
                content_lines.append(f"Description:\n{desc}")
            full_content = "\n".join(content_lines)

            # Scoring: rank-decayed lexical overlap
            overlap = sum(1 for t in q_tokens if t in full_content.lower())
            score = round(float(overlap * 2.0) + (1.0 / (1.0 + rank)), 3)

            metadata = {
                "key": key,
                "status": status_name,
                "issue_type": type_name,
                "priority": priority_name,
                "created": fields.get("created"),
                "updated": fields.get("updated"),
            }

            ev = self.normalize_evidence(
                source_id=key,
                source_type="jira",
                content=full_content,
                uri=f"{self.config.base_url.rstrip('/')}/browse/{key}",
                chunk_index=0,
                metadata=metadata,
                created_at=fields.get("created"),
            )
            evidence_list.append((ev, score))

        evidence_list.sort(key=lambda x: x[1], reverse=True)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        final_hits = evidence_list[:k]
        if final_hits:
            self._set_cached_search(query, k, filters, final_hits)
        return final_hits, elapsed_ms

    def lookup_entity(self, entity_id: str) -> Optional[Evidence]:
        """Direct O(1) fetch for specific ticket key (e.g. 'PROJ-123')."""
        if self.is_circuit_open():
            return None
        url = f"{self.config.base_url.rstrip('/')}/rest/api/2/issue/{entity_id}"
        try:
            res = self._client.get(url)
            if res.status_code == 200:
                data = res.json()
                key = data.get("key", entity_id)
                fields = data.get("fields", {})
                summary = fields.get("summary") or ""
                desc = fields.get("description") or ""
                status_name = (fields.get("status") or {}).get("name", "Unknown")
                content = f"Issue Key: {key}\nStatus: {status_name}\nSummary: {summary}\nDescription:\n{desc}"
                return self.normalize_evidence(
                    source_id=key,
                    source_type="jira",
                    content=content,
                    uri=f"{self.config.base_url.rstrip('/')}/browse/{key}",
                    metadata={"status": status_name, "key": key},
                )
        except Exception:
            return None
        return None

    def health_check(self) -> bool:
        """Verify Jira instance reachability."""
        url = f"{self.config.base_url.rstrip('/')}/rest/api/2/serverInfo"
        try:
            res = self._client.get(url)
            return res.status_code == 200
        except Exception:
            return False

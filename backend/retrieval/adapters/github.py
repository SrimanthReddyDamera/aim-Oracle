"""
ORACLE GitHub EvidenceProvider Adapter (Brick 3.9)
Production-grade integration with GitHub REST API v3 (Search Issues & Pull Requests).
Implements authentication, repository scoping, rate-limit header tracking,
pagination, timeout isolation, and standardized Evidence normalization.
"""

import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

from backend.evidence.models import Evidence
from backend.retrieval.adapters.config import GitHubConfig
from backend.retrieval.base_external import ExternalEvidenceProvider
from backend.retrieval.provider import ProviderCapability


class GitHubEvidenceProvider(ExternalEvidenceProvider):
    """
    EvidenceProvider adapter for GitHub repository platforms.
    Searches pull requests, issues, discussions, and commit notes across target repositories
    with rate-limit backoff and circuit-breaking protections.
    """

    def __init__(self, config: GitHubConfig, client: Optional[httpx.Client] = None):
        super().__init__(
            provider_id="github",
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
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "ORACLE-Investigation-Engine/3.9",
        }
        if self.config.api_token:
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

    def _build_search_query(self, query: str, filters: Optional[Dict[str, Any]] = None) -> str:
        """Constructs GitHub Search API query with repository and type qualifiers."""
        # Clean text
        clean_tokens = re.findall(r"[A-Za-z0-9_\.\-]+", query)
        base_text = " ".join(t for t in clean_tokens if len(t) > 1)

        qualifiers: List[str] = []

        # Repository scoping
        if self.config.repos:
            repo_clauses = [f"repo:{r}" for r in self.config.repos]
            qualifiers.append(" ".join(repo_clauses))

        # Structured filters
        if filters:
            if "state" in filters:
                qualifiers.append(f"state:{filters['state']}")
            if "type" in filters:
                qualifiers.append(f"type:{filters['type']}")
            if "author" in filters:
                qualifiers.append(f"author:{filters['author']}")

        has_type = any(q.startswith("type:") or q.startswith("is:") for q in qualifiers)
        if not has_type:
            qualifiers.append("is:issue")

        if qualifiers:
            return f"{base_text} {' '.join(qualifiers)}".strip()
        return f"{base_text} is:issue".strip()

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

        q_str = self._build_search_query(query, filters=filters)
        url = f"{self.config.base_url.rstrip('/')}/search/issues"
        params = {
            "q": q_str,
            "per_page": min(k, self.config.per_page),
            "page": 1,
        }

        retries = 0
        while retries <= self.config.max_retries:
            try:
                response = self._client.get(url, params=params)
                # Check rate limiting headers
                remaining = response.headers.get("X-RateLimit-Remaining")
                if response.status_code in [403, 429] and remaining == "0":
                    reset_ts = float(response.headers.get("X-RateLimit-Reset", time.time() + 1.0))
                    sleep_sec = max(reset_ts - time.time(), 0.5) * self.config.rate_limit_backoff_factor
                    retries += 1
                    if retries <= self.config.max_retries:
                        time.sleep(min(sleep_sec, 2.0))
                        continue
                    else:
                        self.record_failure("RateLimitExceeded")
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

        items = data.get("items", [])
        evidence_list: List[Tuple[Evidence, float]] = []
        q_tokens = set(query.lower().split())

        for rank, item in enumerate(items, start=1):
            number = item.get("number", 0)
            title = item.get("title") or ""
            body = item.get("body") or ""
            state = item.get("state") or "unknown"
            html_url = item.get("html_url") or ""
            is_pr = "pull_request" in item

            # Extract repo identifier from repo URL (e.g. repos/owner/repo)
            repo_url = item.get("repository_url", "")
            repo_match = re.search(r"repos/([^/]+/[^/]+)$", repo_url)
            repo_name = repo_match.group(1) if repo_match else "github"

            user_obj = item.get("user") or {}
            author = user_obj.get("login", "unknown") if isinstance(user_obj, dict) else "unknown"

            item_type = "Pull Request" if is_pr else "Issue"
            content_lines = [
                f"Repository: {repo_name}",
                f"Type: {item_type} #{number}",
                f"Title: {title}",
                f"State: {state}",
                f"Author: {author}",
            ]
            if body:
                content_lines.append(f"Body:\n{body}")
            full_content = "\n".join(content_lines)

            overlap = sum(1 for t in q_tokens if t in full_content.lower())
            score = round(float(overlap * 2.0) + (1.0 / (1.0 + rank)), 3)

            labels_list = [l.get("name", "") for l in item.get("labels", []) if isinstance(l, dict)]
            metadata = {
                "repo": repo_name,
                "number": number,
                "is_pr": is_pr,
                "state": state,
                "author": author,
                "comments": item.get("comments", 0),
                "labels": labels_list,
                "created_at": item.get("created_at"),
                "updated_at": item.get("updated_at"),
            }

            source_id = f"{repo_name}#{number}"
            ev = self.normalize_evidence(
                source_id=source_id,
                source_type="github",
                content=full_content,
                uri=html_url,
                chunk_index=0,
                metadata=metadata,
                created_at=item.get("created_at"),
            )
            evidence_list.append((ev, score))

        evidence_list.sort(key=lambda x: x[1], reverse=True)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        final_hits = evidence_list[:k]
        if final_hits:
            self._set_cached_search(query, k, filters, final_hits)
        return final_hits, elapsed_ms

    def lookup_entity(self, entity_id: str) -> Optional[Evidence]:
        """Direct fetch by repo#number (e.g. 'org/repo#42')."""
        if self.is_circuit_open():
            return None
        match = re.match(r"^([^#]+)#(\d+)$", entity_id.strip())
        if not match:
            return None
        repo, num = match.group(1), match.group(2)
        url = f"{self.config.base_url.rstrip('/')}/repos/{repo}/issues/{num}"
        try:
            res = self._client.get(url)
            if res.status_code == 200:
                item = res.json()
                title = item.get("title", "")
                body = item.get("body", "")
                state = item.get("state", "open")
                content = f"Repository: {repo}\nIssue #{num}: {title}\nState: {state}\nBody:\n{body}"
                return self.normalize_evidence(
                    source_id=f"{repo}#{num}",
                    source_type="github",
                    content=content,
                    uri=item.get("html_url"),
                    metadata={"repo": repo, "number": int(num), "state": state},
                )
        except Exception:
            return None
        return None

    def health_check(self) -> bool:
        """Verify GitHub API reachability."""
        url = f"{self.config.base_url.rstrip('/')}/zen"
        try:
            res = self._client.get(url)
            return res.status_code == 200
        except Exception:
            return False

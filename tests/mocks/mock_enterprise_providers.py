"""
ORACLE Mock Enterprise Evidence Providers (Brick 3.9)
Deterministic offline mock implementations of Jira, Linear, GitHub, and Slack
for unit testing federated retrieval, timeout handling, and circuit breaking.
"""

import time
from typing import Any, Dict, List, Optional, Tuple

from backend.evidence.models import Evidence
from backend.retrieval.base_external import ExternalEvidenceProvider


class MockJiraProvider(ExternalEvidenceProvider):
    """Simulates enterprise Jira issues with status and component metadata."""

    def __init__(self, issues: Optional[List[Dict[str, Any]]] = None, simulate_timeout: bool = False, simulate_error: bool = False):
        super().__init__(provider_id="mock_jira", timeout_seconds=1.0)
        self.issues = issues or []
        self.simulate_timeout = simulate_timeout
        self.simulate_error = simulate_error

    def search(
        self,
        query: str,
        k: int = 5,
        filters: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[Tuple[Evidence, float]], float]:
        t0 = time.perf_counter()
        if self.simulate_timeout:
            time.sleep(1.2)  # Exceeds 1.0s timeout
            raise TimeoutError("Jira API request timed out")
        if self.simulate_error:
            raise RuntimeError("Jira API returned HTTP 500 Internal Server Error")

        q_tokens = set(query.lower().split())
        hits: List[Tuple[Evidence, float]] = []

        for issue in self.issues:
            key = issue.get("key", "PROJ-1")
            summary = issue.get("summary", "")
            desc = issue.get("description", "")
            status = issue.get("status", "Open")
            content = f"Issue Key: {key}\nSummary: {summary}\nStatus: {status}\nDescription: {desc}"

            # Simple token overlap score
            overlap = sum(1 for t in q_tokens if t in content.lower())
            if overlap > 0:
                ev = self.normalize_evidence(
                    source_id=key,
                    source_type="jira",
                    content=content,
                    uri=f"https://jira.corp.internal/browse/{key}",
                    metadata={"status": status, "priority": issue.get("priority", "Medium")},
                )
                hits.append((ev, float(overlap * 2.5)))

        hits.sort(key=lambda x: x[1], reverse=True)
        return hits[:k], (time.perf_counter() - t0) * 1000.0

    def health_check(self) -> bool:
        return not self.simulate_error


class MockSlackProvider(ExternalEvidenceProvider):
    """Simulates enterprise Slack message threads."""

    def __init__(self, messages: Optional[List[Dict[str, Any]]] = None, simulate_timeout: bool = False):
        super().__init__(provider_id="mock_slack", timeout_seconds=1.0)
        self.messages = messages or []
        self.simulate_timeout = simulate_timeout

    def search(
        self,
        query: str,
        k: int = 5,
        filters: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[Tuple[Evidence, float]], float]:
        t0 = time.perf_counter()
        if self.simulate_timeout:
            time.sleep(1.2)
            raise TimeoutError("Slack Web API timed out")

        q_tokens = set(query.lower().split())
        hits: List[Tuple[Evidence, float]] = []

        for msg in self.messages:
            channel = msg.get("channel", "general")
            ts = msg.get("ts", "1725300000.00")
            text = msg.get("text", "")
            content = f"Channel: #{channel} (ts={ts})\nMessage: {text}"

            overlap = sum(1 for t in q_tokens if t in content.lower())
            if overlap > 0:
                ev = self.normalize_evidence(
                    source_id=f"{channel}-{ts}",
                    source_type="slack",
                    content=content,
                    uri=f"slack://channel/{channel}/thread/{ts}",
                    metadata={"channel": channel, "user": msg.get("user", "user1")},
                )
                hits.append((ev, float(overlap * 1.5)))

        hits.sort(key=lambda x: x[1], reverse=True)
        return hits[:k], (time.perf_counter() - t0) * 1000.0

    def health_check(self) -> bool:
        return True


class MockGitHubProvider(ExternalEvidenceProvider):
    """Simulates GitHub Pull Requests and Issues."""

    def __init__(self, items: Optional[List[Dict[str, Any]]] = None):
        super().__init__(provider_id="mock_github", timeout_seconds=1.0)
        self.items = items or []

    def search(
        self,
        query: str,
        k: int = 5,
        filters: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[Tuple[Evidence, float]], float]:
        t0 = time.perf_counter()
        q_tokens = set(query.lower().split())
        hits: List[Tuple[Evidence, float]] = []

        for item in self.items:
            number = item.get("number", 1)
            title = item.get("title", "")
            body = item.get("body", "")
            state = item.get("state", "open")
            content = f"PR #{number}: {title}\nState: {state}\nBody: {body}"

            overlap = sum(1 for t in q_tokens if t in content.lower())
            if overlap > 0:
                ev = self.normalize_evidence(
                    source_id=f"gh-{number}",
                    source_type="github",
                    content=content,
                    uri=f"https://github.com/org/repo/pull/{number}",
                    metadata={"state": state, "number": number},
                )
                hits.append((ev, float(overlap * 2.0)))

        hits.sort(key=lambda x: x[1], reverse=True)
        return hits[:k], (time.perf_counter() - t0) * 1000.0

    def health_check(self) -> bool:
        return True

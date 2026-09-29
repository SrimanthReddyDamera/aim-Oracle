"""
Deterministic Entity Resolution (Brick 4.3)

Maps incoming enterprise events to active ReleaseCandidates and investigations
using exact, deterministic canonical identifiers (commits, repos, PRs, work items, services).
Controller sovereignty is preserved; LLMs never act as authoritative entity resolvers.
"""

from __future__ import annotations

import threading
from typing import Dict, List, Optional, Set

from backend.release.events.models import EnterpriseEvent
from backend.release.models import ReleaseCandidate


class DeterministicEntityResolver:
    """
    Deterministic registry mapping external enterprise entity keys to active release candidates.
    """

    def __init__(self, store: Optional[Any] = None):
        self._store = store
        self._candidates: Dict[str, ReleaseCandidate] = {}  # release_id -> candidate
        self._lock = threading.RLock()

    def register_candidate(self, candidate: ReleaseCandidate) -> None:
        """Register an active release candidate for event tracking."""
        with self._lock:
            self._candidates[candidate.release_id] = candidate

    def unregister_candidate(self, release_id: str) -> None:
        """Unregister a concluded release candidate."""
        with self._lock:
            self._candidates.pop(release_id, None)

    def get_candidate(self, release_id: str) -> Optional[ReleaseCandidate]:
        with self._lock:
            return self._candidates.get(release_id)

    def list_candidates(self) -> List[ReleaseCandidate]:
        with self._lock:
            return list(self._candidates.values())

    def resolve_affected_releases(self, event: EnterpriseEvent) -> List[ReleaseCandidate]:
        """
        Deterministically resolve which active release candidates are affected by the event.
        Zero LLM guesswork; strictly grounded in canonical entity attributes.
        """
        with self._lock:
            candidates = list(self._candidates.values())

        event_tenant = getattr(event, "tenant_id", "default")
        if self._store and hasattr(self._store, "entities") and self._store.entities:
            try:
                persisted = self._store.entities.list_candidates(tenant_id=event_tenant)
                mem_ids = {c.release_id for c in candidates}
                for pc in persisted:
                    if pc.release_id not in mem_ids:
                        candidates.append(pc)
            except Exception:
                pass

        matched: List[ReleaseCandidate] = []
        seen_ids: Set[str] = set()

        event_tenant = getattr(event, "tenant_id", "default")
        for c in candidates:
            cand_tenant = getattr(c, "tenant_id", "default")
            if cand_tenant != event_tenant:
                continue

            is_match = False

            # 1. Direct release_id match
            if event.release_id and event.release_id == c.release_id:
                is_match = True

            # 2. Exact Commit & Repository Match
            elif event.commit and event.commit == c.commit:
                if not event.repository or event.repository.lower() == c.repository.lower():
                    is_match = True

            # 3. Pull Request Match on same repository
            elif event.repository and event.repository.lower() == c.repository.lower():
                pr_nums = [str(c.pull_request_id or "")]
                if hasattr(c, "pull_request_ids") and getattr(c, "pull_request_ids", None):
                    pr_nums.extend([str(p) for p in getattr(c, "pull_request_ids", [])])
                clean_pr_nums = {p.replace("PR-", "").strip() for p in pr_nums if p}
                event_pr_clean = event.entity_id.replace("PR-", "").strip()

                if event_pr_clean and event_pr_clean in clean_pr_nums:
                    is_match = True

                # Check if event commit matches candidate commit
                elif event.entity_type == "commit" and event.entity_id == c.commit:
                    is_match = True

                # If commit push happened on same repo
                elif event.event_type.value == "CODE_PUSHED":
                    is_match = True

            # 4. Work Item / Jira key Match
            elif event.work_item_id and event.work_item_id in c.linked_work_item_ids:
                is_match = True
            elif event.entity_type == "work_item" and event.entity_id in c.linked_work_item_ids:
                is_match = True

            # 5. Service-level Incidents
            elif event.entity_type == "incident":
                affected_services = event.correlation_keys.get("affected_services", [])
                if c.service_name in affected_services or event.service_id == c.service_name or not event.service_id:
                    is_match = True

            # 6. Service ID match
            elif event.service_id and event.service_id == c.service_name:
                is_match = True

            if is_match and c.release_id not in seen_ids:
                matched.append(c)
                seen_ids.add(c.release_id)

        return matched

"""
Enterprise Event Normalizers (Brick 4.3)

Translates vendor-specific webhook payloads (GitHub, Jira Cloud, Semgrep, Trivy)
into canonical, provider-neutral EnterpriseEvent models.
Ensures external raw payload structures do not leak into the deterministic controller.
"""

from __future__ import annotations

import abc
import hashlib
import json
import time
from typing import Any, Dict, List, Optional

from backend.release.connectivity.credentials import GLOBAL_REDACTOR
from backend.release.events.models import EnterpriseEvent, EnterpriseEventType


class EventNormalizer(abc.ABC):
    """Abstract normalizer contract for enterprise event sources."""

    @abc.abstractmethod
    def can_handle(self, source: str, event_name: str, payload: Dict[str, Any]) -> bool:
        """Check if this normalizer handles the given provider source and event."""
        pass

    @abc.abstractmethod
    def normalize(
        self,
        source: str,
        event_name: str,
        payload: Dict[str, Any],
        headers: Optional[Dict[str, str]] = None,
    ) -> List[EnterpriseEvent]:
        """Normalize raw payload into one or more canonical EnterpriseEvent instances."""
        pass


class GitHubEventNormalizer(EventNormalizer):
    """Normalizes GitHub webhooks (push, pull_request, workflow_run, pull_request_review)."""

    def can_handle(self, source: str, event_name: str, payload: Dict[str, Any]) -> bool:
        return source.lower() in ("github", "github_actions")

    def normalize(
        self,
        source: str,
        event_name: str,
        payload: Dict[str, Any],
        headers: Optional[Dict[str, str]] = None,
    ) -> List[EnterpriseEvent]:
        headers = headers or {}
        event_header = headers.get("x-github-event") or headers.get("X-GitHub-Event") or event_name
        delivery_id = headers.get("x-github-delivery") or headers.get("X-GitHub-Delivery") or payload.get("delivery_id")
        now_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # Payload reference hash (no raw dumping)
        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        payload_ref = hashlib.sha256(payload_bytes).hexdigest()

        repo_info = payload.get("repository", {})
        repo_name = repo_info.get("full_name") or repo_info.get("name", "")

        events: List[EnterpriseEvent] = []

        # 1. PUSH EVENT
        if event_header == "push":
            commit_sha = payload.get("after") or payload.get("head_commit", {}).get("id") or ""
            ref = payload.get("ref", "")
            branch = ref.replace("refs/heads/", "") if "refs/heads/" in ref else ref
            source_evt_id = delivery_id or f"push-{commit_sha[:10]}"

            events.append(
                EnterpriseEvent(
                    event_type=EnterpriseEventType.CODE_PUSHED,
                    source="github",
                    source_event_id=str(source_evt_id),
                    timestamp=payload.get("head_commit", {}).get("timestamp") or now_ts,
                    entity_type="commit",
                    entity_id=commit_sha,
                    repository=repo_name,
                    commit=commit_sha,
                    correlation_keys={"branch": branch, "ref": ref},
                    payload_reference=payload_ref,
                    provenance={"provider": "github", "event": "push"},
                )
            )

        # 2. PULL REQUEST EVENT
        elif event_header == "pull_request":
            action = payload.get("action", "")
            pr_data = payload.get("pull_request", {})
            pr_number = str(pr_data.get("number") or payload.get("number", ""))
            head_sha = pr_data.get("head", {}).get("sha", "")
            source_evt_id = delivery_id or f"pr-{pr_number}-{action}"

            evt_type = EnterpriseEventType.PR_UPDATED
            if action == "opened":
                evt_type = EnterpriseEventType.PR_CREATED
            elif action == "closed" and pr_data.get("merged", False):
                evt_type = EnterpriseEventType.PR_MERGED
            elif action in ("synchronize", "reopened"):
                evt_type = EnterpriseEventType.PR_UPDATED

            events.append(
                EnterpriseEvent(
                    event_type=evt_type,
                    source="github",
                    source_event_id=str(source_evt_id),
                    timestamp=pr_data.get("updated_at") or pr_data.get("created_at") or now_ts,
                    entity_type="pull_request",
                    entity_id=f"PR-{pr_number}",
                    repository=repo_name,
                    commit=head_sha,
                    correlation_keys={"action": action, "pr_number": pr_number, "merged": pr_data.get("merged", False)},
                    payload_reference=payload_ref,
                    provenance={"provider": "github", "event": "pull_request"},
                )
            )

        # 3. PULL REQUEST REVIEW EVENT
        elif event_header == "pull_request_review":
            action = payload.get("action", "")
            review = payload.get("review", {})
            state = review.get("state", "").upper()
            pr_data = payload.get("pull_request", {})
            pr_number = str(pr_data.get("number") or "")
            head_sha = pr_data.get("head", {}).get("sha", "")
            source_evt_id = delivery_id or f"review-{review.get('id', pr_number)}"

            if state == "APPROVED":
                evt_type = EnterpriseEventType.PR_APPROVED
            elif state in ("CHANGES_REQUESTED", "REJECTED"):
                evt_type = EnterpriseEventType.PR_REJECTED
            else:
                evt_type = EnterpriseEventType.PR_UPDATED

            events.append(
                EnterpriseEvent(
                    event_type=evt_type,
                    source="github",
                    source_event_id=str(source_evt_id),
                    timestamp=review.get("submitted_at") or now_ts,
                    entity_type="pull_request",
                    entity_id=f"PR-{pr_number}",
                    repository=repo_name,
                    commit=head_sha,
                    correlation_keys={"reviewer": review.get("user", {}).get("login"), "state": state},
                    payload_reference=payload_ref,
                    provenance={"provider": "github", "event": "pull_request_review"},
                )
            )

        # 4. WORKFLOW RUN EVENT (CI/CD)
        elif event_header in ("workflow_run", "check_run", "check_suite"):
            wf_run = payload.get("workflow_run") or payload.get("check_run", {})
            run_id = str(wf_run.get("id") or "")
            status = wf_run.get("status", "").lower()
            conclusion = (wf_run.get("conclusion") or "").lower()
            head_sha = wf_run.get("head_sha") or wf_run.get("head_commit", {}).get("id") or ""
            source_evt_id = delivery_id or f"wf-{run_id}-{status}-{conclusion}"

            if conclusion == "success":
                evt_type = EnterpriseEventType.CI_SUCCEEDED
            elif conclusion in ("failure", "timed_out", "cancelled"):
                evt_type = EnterpriseEventType.CI_FAILED
            elif status in ("in_progress", "queued", "requested"):
                evt_type = EnterpriseEventType.CI_STARTED
            else:
                evt_type = EnterpriseEventType.CI_COMPLETED

            events.append(
                EnterpriseEvent(
                    event_type=evt_type,
                    source="github_actions",
                    source_event_id=str(source_evt_id),
                    timestamp=wf_run.get("updated_at") or wf_run.get("created_at") or now_ts,
                    entity_type="pipeline",
                    entity_id=f"GHA-{run_id}",
                    repository=repo_name,
                    commit=head_sha,
                    correlation_keys={"run_id": run_id, "conclusion": conclusion, "status": status},
                    payload_reference=payload_ref,
                    provenance={"provider": "github_actions", "event": event_header},
                )
            )

        return events


class JiraEventNormalizer(EventNormalizer):
    """Normalizes Jira Cloud webhooks (issue_created, issue_updated, changelog)."""

    def can_handle(self, source: str, event_name: str, payload: Dict[str, Any]) -> bool:
        return source.lower() == "jira" or "webhookEvent" in payload

    def normalize(
        self,
        source: str,
        event_name: str,
        payload: Dict[str, Any],
        headers: Optional[Dict[str, str]] = None,
    ) -> List[EnterpriseEvent]:
        now_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        webhook_event = payload.get("webhookEvent", event_name)
        issue = payload.get("issue", {})
        issue_key = issue.get("key") or payload.get("issue_key", "")

        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        payload_ref = hashlib.sha256(payload_bytes).hexdigest()

        fields = issue.get("fields", {})
        status_name = fields.get("status", {}).get("name", "").upper()
        priority_name = fields.get("priority", {}).get("name", "").upper()
        issue_type = fields.get("issuetype", {}).get("name", "").lower()
        is_incident = "incident" in issue_type or issue_key.startswith("INC-")

        # Changelog inspection to see what changed
        changelog = payload.get("changelog", {}).get("items", [])
        changed_fields = [item.get("field", "").lower() for item in changelog]
        to_status = ""
        from_status = ""
        for item in changelog:
            if item.get("field", "").lower() == "status":
                to_status = item.get("toString", "")
                from_status = item.get("fromString", "")

        source_evt_id = payload.get("timestamp") or f"{issue_key}-{int(time.time() * 1000)}"

        # Determine canonical event type
        if is_incident:
            if "status" in changed_fields and status_name in ("DONE", "RESOLVED", "CLOSED"):
                evt_type = EnterpriseEventType.INCIDENT_RESOLVED
            elif webhook_event == "jira:issue_created":
                evt_type = EnterpriseEventType.INCIDENT_OPENED
            else:
                evt_type = EnterpriseEventType.INCIDENT_UPDATED
        elif "status" in changed_fields:
            evt_type = EnterpriseEventType.JIRA_STATUS_CHANGED
        elif "priority" in changed_fields or "blocker" in status_name.lower():
            evt_type = EnterpriseEventType.JIRA_BLOCKER_CHANGED
        elif webhook_event == "jira:issue_created":
            evt_type = EnterpriseEventType.JIRA_ISSUE_CREATED
        else:
            evt_type = EnterpriseEventType.JIRA_ISSUE_UPDATED

        return [
            EnterpriseEvent(
                event_type=evt_type,
                source="jira",
                source_event_id=str(source_evt_id),
                timestamp=issue.get("fields", {}).get("updated") or now_ts,
                entity_type="incident" if is_incident else "work_item",
                entity_id=issue_key,
                work_item_id=issue_key,
                correlation_keys={
                    "status": status_name,
                    "priority": priority_name,
                    "is_incident": is_incident,
                    "changed_fields": changed_fields,
                    "to_status": to_status or status_name,
                    "from_status": from_status,
                },
                payload_reference=payload_ref,
                provenance={"provider": "jira", "webhookEvent": webhook_event},
            )
        ]


class SecurityEventNormalizer(EventNormalizer):
    """Normalizes Semgrep and Trivy security findings events."""

    def can_handle(self, source: str, event_name: str, payload: Dict[str, Any]) -> bool:
        return source.lower() in ("semgrep", "trivy", "security")

    def normalize(
        self,
        source: str,
        event_name: str,
        payload: Dict[str, Any],
        headers: Optional[Dict[str, str]] = None,
    ) -> List[EnterpriseEvent]:
        now_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        finding_id = payload.get("finding_id") or payload.get("check_id") or payload.get("id", "VULN-001")
        action = payload.get("action", event_name).lower()
        commit = payload.get("commit") or payload.get("head_sha", "")
        repo = payload.get("repository") or payload.get("repo", "")

        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        payload_ref = hashlib.sha256(payload_bytes).hexdigest()

        if action in ("resolved", "fixed", "muted"):
            evt_type = EnterpriseEventType.SECURITY_FINDING_RESOLVED
        elif action in ("updated", "re-triaged"):
            evt_type = EnterpriseEventType.SECURITY_FINDING_UPDATED
        else:
            evt_type = EnterpriseEventType.SECURITY_FINDING_CREATED

        source_evt_id = payload.get("event_id") or f"{finding_id}-{action}-{int(time.time()*1000)}"

        return [
            EnterpriseEvent(
                event_type=evt_type,
                source=source.lower(),
                source_event_id=str(source_evt_id),
                timestamp=payload.get("timestamp") or now_ts,
                entity_type="security_finding",
                entity_id=str(finding_id),
                repository=repo,
                commit=commit,
                correlation_keys={
                    "severity": payload.get("severity", "HIGH").upper(),
                    "cwe": payload.get("cwe"),
                    "action": action,
                },
                payload_reference=payload_ref,
                provenance={"provider": source.lower(), "action": action},
            )
        ]

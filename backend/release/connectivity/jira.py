"""
Production Jira Work Management Provider (Bricks 4.1 & 4.2)

Connects to Jira Cloud REST API (v3) with:
1. Resilient HTTP transport (circuit breaker, retries, rate-limits)
2. Token-based authentication via CredentialProvider
3. Configurable field mappings (JiraFieldMappingConfig) to support enterprise custom fields without controller leaks
4. Issue status, priority, blockers, approvals, and active incident discovery via dynamic JQL
5. Canonical Evidence normalization with SHA-256 hashes and byte-level offsets
"""

from __future__ import annotations

import base64
from typing import Any, Dict, List, Optional

import httpx

from backend.evidence.models import Evidence
from backend.release.config import JiraFieldMappingConfig
from backend.release.connectivity.credentials import CredentialProvider, EnvCredentialProvider, GLOBAL_REDACTOR
from backend.release.connectivity.resilience import ResilientHttpClient
from backend.release.models import ReleaseCandidate, WorkItem, WorkItemStatus
from backend.release.providers import WorkManagementProvider, _create_evidence


class JiraWorkManagementProvider(WorkManagementProvider):
    """
    Production-quality Jira Work Management & Incident Provider.
    Queries Jira Cloud REST API v3 and normalizes results into canonical ORACLE models.
    Supports enterprise custom field variability via JiraFieldMappingConfig.
    """

    def __init__(
        self,
        credential_provider: Optional[CredentialProvider] = None,
        base_url: str = "https://corp.atlassian.net",
        mapping_config: Optional[JiraFieldMappingConfig] = None,
        client: Optional[ResilientHttpClient] = None,
        transport: Optional[httpx.BaseTransport] = None,
    ):
        self.credential_provider = credential_provider or EnvCredentialProvider()
        self.base_url = base_url.rstrip("/")
        self.mapping = mapping_config or JiraFieldMappingConfig()
        self.client = client or ResilientHttpClient(
            provider_id="jira",
            base_url=self.base_url,
            transport=transport,
        )

    def _get_auth_headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "ORACLE-Intelligence-Engine/4.2",
        }
        token = self.credential_provider.get_token("jira")
        if token:
            if ":" in token:
                # Basic Auth username:api_token
                encoded = base64.b64encode(token.encode("utf-8")).decode("ascii")
                headers["Authorization"] = f"Basic {encoded}"
            else:
                headers["Authorization"] = f"Bearer {token}"
        return headers

    def _extract_users(self, value: Any) -> List[str]:
        """Extract user identifiers from list of strings, dicts, or comma-separated strings."""
        if not value:
            return []
        users: List[str] = []
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    users.append(item.strip())
                elif isinstance(item, dict):
                    name = item.get("displayName") or item.get("name") or item.get("accountId")
                    if name:
                        users.append(str(name).strip())
        elif isinstance(value, str):
            for part in value.split(","):
                clean = part.strip()
                if clean:
                    users.append(clean)
        elif isinstance(value, dict):
            name = value.get("displayName") or value.get("name") or value.get("accountId")
            if name:
                users.append(str(name).strip())
        return users

    def get_work_item(self, item_id: str) -> Optional[WorkItem]:
        """Fetch real WorkItem / issue from Jira Cloud API and normalize using JiraFieldMappingConfig."""
        headers = self._get_auth_headers()
        url = f"/rest/api/3/issue/{item_id}"
        resp = self.client.request("GET", url, headers=headers)
        if resp.status_code == 404:
            return None
        data = resp.json()

        fields = data.get("fields", {})

        # Summary
        summary = fields.get(self.mapping.summary_field, "")

        # Status & Category
        status_obj = fields.get(self.mapping.status_field, {})
        status_name = status_obj.get("name", "Open").upper()
        status_category = (
            status_obj.get("statusCategory", {}).get("name", "").lower()
        )

        # Priority & Issue Type
        priority_obj = fields.get(self.mapping.priority_field, {})
        priority_name = priority_obj.get("name", "Normal").upper() if isinstance(priority_obj, dict) else str(priority_obj).upper()

        issuetype_obj = fields.get(self.mapping.issuetype_field, {})
        issue_type = issuetype_obj.get("name", "").lower() if isinstance(issuetype_obj, dict) else str(issuetype_obj).lower()

        # Map to canonical status using configured names
        if (
            status_name in self.mapping.done_status_names
            or "done" in status_category
        ):
            canonical_status = WorkItemStatus.DONE
        elif (
            status_name in self.mapping.blocked_status_names
            or "blocked" in status_name.lower()
        ):
            canonical_status = WorkItemStatus.BLOCKED
        elif (
            status_name in self.mapping.rejected_status_names
            or "rejected" in status_name.lower()
            or "wontfix" in status_name.lower()
        ):
            canonical_status = WorkItemStatus.REJECTED
        elif (
            status_name in self.mapping.in_progress_status_names
            or "in progress" in status_category
        ):
            canonical_status = WorkItemStatus.IN_PROGRESS
        else:
            canonical_status = WorkItemStatus.OPEN

        is_incident = "incident" in issue_type or item_id.startswith("INC-")
        is_blocking = (
            priority_name in self.mapping.blocking_priorities
            or canonical_status == WorkItemStatus.BLOCKED
            or is_incident
        )

        # Extract approvals / rejections from labels
        labels = [str(l).lower() for l in fields.get(self.mapping.labels_field, [])]
        approvals: List[str] = []
        rejections: List[str] = []
        for l in labels:
            if l.startswith("approved-by-"):
                approvals.append(l.replace("approved-by-", ""))
            elif l.startswith("rejected-by-"):
                rejections.append(l.replace("rejected-by-", ""))

        # Also extract approvals / rejections from configured custom fields
        for app_field in self.mapping.approval_fields:
            val = fields.get(app_field)
            if val:
                approvals.extend(self._extract_users(val))

        for rej_field in self.mapping.rejection_fields:
            val = fields.get(rej_field)
            if val:
                rejections.extend(self._extract_users(val))

        # Deduplicate while preserving order
        approvals = list(dict.fromkeys(approvals))
        rejections = list(dict.fromkeys(rejections))

        assignee_obj = fields.get(self.mapping.assignee_field, {})
        owner = "unassigned"
        if isinstance(assignee_obj, dict):
            owner = assignee_obj.get("displayName") or assignee_obj.get("name") or "unassigned"
        elif isinstance(assignee_obj, str) and assignee_obj:
            owner = assignee_obj

        created_ts = fields.get(self.mapping.created_field, "")

        return WorkItem(
            item_id=item_id,
            title=summary,
            status=canonical_status,
            priority=priority_name,
            is_blocking=is_blocking,
            is_incident=is_incident,
            owner=owner,
            approvals=approvals,
            rejections=rejections,
            timestamp=created_ts,
            provenance={"provider": "jira", "key": item_id},
        )

    def get_active_incidents_for_service(self, service_name: str) -> List[WorkItem]:
        """Query Jira for active non-Done incidents affecting target service using configurable JQL."""
        headers = self._get_auth_headers()
        url = "/rest/api/3/search"
        jql_query = self.mapping.incident_jql_template.format(service_name=service_name)
        payload = {"jql": jql_query, "maxResults": 20}

        resp = self.client.request("POST", url, headers=headers, json_data=payload)
        if resp.status_code != 200:
            return []

        search_data = resp.json()
        issues = search_data.get("issues", [])
        incidents: List[WorkItem] = []

        for issue in issues:
            key = issue.get("key")
            if key:
                item = self.get_work_item(key)
                if item and item.status != WorkItemStatus.DONE:
                    item.is_incident = True
                    item.linked_releases = [service_name]
                    incidents.append(item)

        return incidents

    def fetch_evidence_for_release(self, candidate: ReleaseCandidate) -> List[Evidence]:
        """Aggregate Jira work items and active incidents for candidate."""
        evidence_list: List[Evidence] = []

        # 1. Linked work items
        for item_id in candidate.linked_work_item_ids:
            item = self.get_work_item(item_id)
            if item:
                app_clause = (
                    f"Approvals: {', '.join(item.approvals)}."
                    if item.approvals
                    else "No approvals recorded."
                )
                rej_clause = (
                    f"Rejections: {', '.join(item.rejections)}."
                    if item.rejections
                    else ""
                )
                raw_content = (
                    f"Work Item {item.item_id}: {item.title}.\n"
                    f"Status: {item.status.value}. Priority: {item.priority}.\n"
                    f"Blocking: {item.is_blocking}. Incident: {item.is_incident}.\n"
                    f"Owner: {item.owner}.\n"
                    f"{app_clause} {rej_clause}".strip()
                )
                clean_content = GLOBAL_REDACTOR.redact(raw_content)

                evidence_list.append(
                    _create_evidence(
                        evidence_id=f"WORK-{item.item_id}",
                        source_id="jira.corp.internal",
                        source_type="jira",
                        content=clean_content,
                        metadata={
                            "item_id": item.item_id,
                            "status": item.status.value,
                            "priority": item.priority,
                            "is_blocking": item.is_blocking,
                            "approvals": item.approvals,
                            "rejections": item.rejections,
                        },
                        timestamp=item.timestamp or candidate.created_at,
                    )
                )

        # 2. Active Incidents for service
        incidents = self.get_active_incidents_for_service(candidate.service_name)
        for inc in incidents:
            raw_content = (
                f"ACTIVE INCIDENT {inc.item_id}: {inc.title}.\n"
                f"Service Affected: {candidate.service_name}.\n"
                f"Status: {inc.status.value}. Priority: {inc.priority}."
            )
            clean_content = GLOBAL_REDACTOR.redact(raw_content)

            evidence_list.append(
                _create_evidence(
                    evidence_id=f"INCIDENT-{inc.item_id}",
                    source_id="incident.corp.internal",
                    source_type="incident",
                    content=clean_content,
                    metadata={
                        "incident_id": inc.item_id,
                        "priority": inc.priority,
                        "status": inc.status.value,
                    },
                    timestamp=inc.timestamp or candidate.created_at,
                )
            )

        return evidence_list

"""
Investigation Impact Analysis Engine (Brick 4.3)

Analyzes an incoming EnterpriseEvent against active investigations and determines
precisely which evidence items, DAG gap nodes, and milestones have become stale or invalidated.
Enforces targeted re-investigation: unaffected portions of the DAG are never re-evaluated unnecessarily.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field

from backend.evidence.models import Evidence
from backend.release.events.models import EnterpriseEvent, EnterpriseEventType
from backend.release.investigation import ReleaseInvestigationResult
from backend.release.models import ReleaseCandidate


class ImpactAnalysisResult(BaseModel):
    """Deliverable of impact analysis detailing affected gaps and stale evidence."""
    event_id: str
    event_type: EnterpriseEventType
    affected_release_ids: List[str] = Field(default_factory=list)
    affected_gap_ids: List[str] = Field(default_factory=list)
    invalidated_evidence_ids: List[str] = Field(default_factory=list)
    reason: str
    requires_reinvestigation: bool = True
    metadata: Dict[str, Any] = Field(default_factory=dict)


class InvestigationImpactAnalyzer:
    """
    Evaluates enterprise events to deduce precise DAG and evidence invalidation scopes.
    """

    def analyze_impact(
        self,
        event: EnterpriseEvent,
        candidate: ReleaseCandidate,
        previous_result: Optional[ReleaseInvestigationResult] = None,
    ) -> ImpactAnalysisResult:
        """
        Determine which gaps and evidence in the candidate's investigation are invalidated by event.
        """
        affected_gaps: Set[str] = set()
        stale_evidence_ids: Set[str] = set()
        reason_parts: List[str] = []

        # Find previous evidence if available
        admitted_evs = previous_result.admitted_evidence if previous_result else []

        # ---------------------------------------------------------------------
        # 1. SOURCE CONTROL: CODE PUSH / PR EVENTS
        # ---------------------------------------------------------------------
        if event.event_type == EnterpriseEventType.CODE_PUSHED:
            # Code push to repository changes commit binding
            affected_gaps.add("GAP-CI-VALIDATION")
            affected_gaps.add("GAP-SECURITY-SAST")
            affected_gaps.add("GAP-SECURITY-SCA")
            affected_gaps.add("GAP-CODE-REVIEW")
            reason_parts.append(f"Code pushed to commit {event.commit[:10] if event.commit else 'new'} invalidates prior CI, security, and review state.")

            # Invalidate CI and security evidence bound to older commit
            for ev in admitted_evs:
                st = ev.source_type.lower()
                ev_commit = (ev.metadata or {}).get("commit")
                if ("ci" in st or "security" in st) and ev_commit and event.commit and ev_commit != event.commit:
                    stale_evidence_ids.add(ev.evidence_id)

        elif event.event_type in (
            EnterpriseEventType.PR_UPDATED,
            EnterpriseEventType.PR_APPROVED,
            EnterpriseEventType.PR_REJECTED,
            EnterpriseEventType.PR_MERGED,
            EnterpriseEventType.PR_CREATED,
        ):
            affected_gaps.add("GAP-CODE-REVIEW")
            affected_gaps.add("GAP-ROLLBACK-PLAN")
            reason_parts.append(f"Pull request update ({event.event_type.value}) invalidates code review and rollback plan status.")

            for ev in admitted_evs:
                if "git" in ev.source_type.lower():
                    stale_evidence_ids.add(ev.evidence_id)

        # ---------------------------------------------------------------------
        # 2. WORK MANAGEMENT: JIRA / LINEAR ISSUES
        # ---------------------------------------------------------------------
        elif event.event_type in (
            EnterpriseEventType.JIRA_STATUS_CHANGED,
            EnterpriseEventType.JIRA_BLOCKER_CHANGED,
            EnterpriseEventType.JIRA_ISSUE_CREATED,
            EnterpriseEventType.JIRA_ISSUE_UPDATED,
        ):
            affected_gaps.add("GAP-WORK-ITEMS")
            reason_parts.append(f"Work item {event.entity_id} state change ({event.event_type.value}) invalidates work item readiness.")

            for ev in admitted_evs:
                if "jira" in ev.source_type.lower() and (ev.metadata or {}).get("item_id") == event.entity_id:
                    stale_evidence_ids.add(ev.evidence_id)

        # ---------------------------------------------------------------------
        # 3. CI/CD: PIPELINE RUNS
        # ---------------------------------------------------------------------
        elif event.event_type in (
            EnterpriseEventType.CI_COMPLETED,
            EnterpriseEventType.CI_FAILED,
            EnterpriseEventType.CI_SUCCEEDED,
            EnterpriseEventType.CI_STARTED,
        ):
            affected_gaps.add("GAP-CI-VALIDATION")
            reason_parts.append(f"CI/CD pipeline event ({event.event_type.value}) invalidates automated test validation state.")

            for ev in admitted_evs:
                if "ci" in ev.source_type.lower():
                    stale_evidence_ids.add(ev.evidence_id)

        # ---------------------------------------------------------------------
        # 4. SECURITY FINDINGS & SCANS
        # ---------------------------------------------------------------------
        elif event.event_type in (
            EnterpriseEventType.SECURITY_FINDING_CREATED,
            EnterpriseEventType.SECURITY_FINDING_UPDATED,
            EnterpriseEventType.SECURITY_FINDING_RESOLVED,
            EnterpriseEventType.SECURITY_SCAN_COMPLETED,
        ):
            # Target SAST or SCA based on correlation keys or default to both
            is_sca = "sca" in event.entity_id.lower() or "dependency" in event.entity_id.lower()
            if is_sca:
                affected_gaps.add("GAP-SECURITY-SCA")
            elif event.event_type == EnterpriseEventType.SECURITY_SCAN_COMPLETED:
                affected_gaps.add("GAP-SECURITY-SAST")
                affected_gaps.add("GAP-SECURITY-SCA")
            else:
                affected_gaps.add("GAP-SECURITY-SAST")

            reason_parts.append(f"Security event ({event.event_type.value}) on {event.entity_id} invalidates security verification.")

            for ev in admitted_evs:
                if "security" in ev.source_type.lower():
                    if (ev.metadata or {}).get("finding_id") == event.entity_id or event.event_type == EnterpriseEventType.SECURITY_SCAN_COMPLETED:
                        stale_evidence_ids.add(ev.evidence_id)

        # ---------------------------------------------------------------------
        # 5. DEPENDENCY & ARTIFACT EVENTS
        # ---------------------------------------------------------------------
        elif event.event_type == EnterpriseEventType.DEPENDENCY_CHANGED:
            affected_gaps.add("GAP-SECURITY-SCA")
            reason_parts.append(f"Dependency change event ({event.entity_id}) invalidates dependency security status.")
            for ev in admitted_evs:
                if "security" in ev.source_type.lower() and "sca" in str((ev.metadata or {}).get("category", "")).lower():
                    stale_evidence_ids.add(ev.evidence_id)

        elif event.event_type in (EnterpriseEventType.ARTIFACT_BUILT, EnterpriseEventType.DEPLOYMENT_CHANGED):
            affected_gaps.add("GAP-SECURITY-SCA")
            affected_gaps.add("GAP-CI-VALIDATION")
            reason_parts.append(f"Artifact/deployment event ({event.event_type.value}) invalidates build artifact security state.")

        elif event.event_type in (EnterpriseEventType.RUNTIME_EXPOSURE_CHANGED, EnterpriseEventType.SECURITY_CONTROL_CHANGED):
            affected_gaps.add("GAP-SECURITY-SAST")
            affected_gaps.add("GAP-SECURITY-SCA")
            reason_parts.append(f"Runtime security posture event ({event.event_type.value}) on {event.entity_id or event.service_id or 'runtime'} invalidates security exposure and impact evaluation.")
            for ev in admitted_evs:
                if "security" in ev.source_type.lower() or "exposure" in ev.source_type.lower():
                    stale_evidence_ids.add(ev.evidence_id)

        # ---------------------------------------------------------------------
        # 6. INCIDENTS & OPERATIONS
        # ---------------------------------------------------------------------
        elif event.event_type in (
            EnterpriseEventType.INCIDENT_CREATED,
            EnterpriseEventType.INCIDENT_OPENED,
            EnterpriseEventType.INCIDENT_UPDATED,
            EnterpriseEventType.INCIDENT_RESOLVED,
        ):
            affected_gaps.add("GAP-INCIDENT-CLEAR")
            reason_parts.append(f"Production incident event ({event.event_type.value}) on {event.entity_id} invalidates operational readiness.")

            for ev in admitted_evs:
                if "incident" in ev.source_type.lower() or (ev.metadata or {}).get("incident_id") == event.entity_id:
                    stale_evidence_ids.add(ev.evidence_id)

        requires_reinvestigation = len(affected_gaps) > 0

        return ImpactAnalysisResult(
            event_id=event.event_id,
            event_type=event.event_type,
            affected_release_ids=[candidate.release_id],
            affected_gap_ids=sorted(list(affected_gaps)),
            invalidated_evidence_ids=sorted(list(stale_evidence_ids)),
            reason="; ".join(reason_parts) if reason_parts else f"No direct impact detected for {event.event_type.value}.",
            requires_reinvestigation=requires_reinvestigation,
        )

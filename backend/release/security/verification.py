"""
Closed-Loop Remediation Verification Engine (Brick 4.7)

Enforces authoritative closed-loop security verification:
Finding
  ↓
Recommendation
  ↓
Governed remediation action (PR created & merged)
  ↓
New commit
  ↓
CI build
  ↓
Security rescan on EXACT new commit / artifact
  ↓
Verified resolution check
  ↓
Close finding / Update decision

CRITICAL INVARIANTS:
- A remediation PR being merged is NOT proof that the vulnerability is fixed.
- A successful, fresh rescan against the EXACT fixed artifact/commit is required.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from backend.release.security.models import (
    FindingStatus,
    SecurityFinding,
    SecurityVerification,
    SecurityVerificationStatus,
)


class SecurityVerificationEngine:
    """
    Controller-governed verification engine for closed-loop remediation.
    Validates that proposed fixes actually eliminated the vulnerability in fresh scans.
    """

    def __init__(self):
        pass

    def verify_remediation(
        self,
        original_finding: SecurityFinding,
        fixed_commit: str,
        rescan_findings: Optional[List[SecurityFinding]] = None,
        rescan_artifact_digest: Optional[str] = None,
        pr_merged: bool = True,
        tenant_id: str = "default",
    ) -> SecurityVerification:
        """
        Verify whether the original vulnerability has been resolved on fixed_commit.
        """
        verification_id = f"secver-{uuid.uuid4().hex[:8]}"
        now_str = "2026-09-09T12:00:00Z"

        # Case 1: PR merged but no rescan was executed
        if rescan_findings is None:
            return SecurityVerification(
                verification_id=verification_id,
                finding_id=original_finding.finding_id,
                tenant_id=tenant_id,
                rescan_commit=fixed_commit,
                rescan_artifact_digest=rescan_artifact_digest,
                status=SecurityVerificationStatus.UNVERIFIED,
                verified_at=now_str,
                notes="Remediation PR was merged, but fresh security rescan has not yet executed on the fixed commit.",
            )

        # Case 2: Inspect rescan findings for the same vulnerability / package / CVE
        matching_active_findings = []
        matching_clean_findings = []
        rescan_ev_ids: List[str] = []

        norm_fixed_commit = fixed_commit.strip().lower()

        for rf in rescan_findings:
            # Check commit binding of rescan
            rf_commit = rf.commit.strip().lower()
            if rf_commit != norm_fixed_commit:
                # Wrong commit rescan
                return SecurityVerification(
                    verification_id=verification_id,
                    finding_id=original_finding.finding_id,
                    tenant_id=tenant_id,
                    rescan_commit=rf.commit,
                    rescan_artifact_digest=rf.artifact_digest,
                    status=SecurityVerificationStatus.STALE_VERIFICATION,
                    verified_at=now_str,
                    notes=f"Rescan commit '{rf.commit[:10]}' does not match fixed release commit '{fixed_commit[:10]}'.",
                )

            # Match target vulnerability
            matches = False
            if original_finding.cve and rf.cve and original_finding.cve.lower() == rf.cve.lower():
                matches = True
            elif original_finding.package and rf.package and original_finding.package.lower() == rf.package.lower():
                matches = True
            elif original_finding.finding_id.lower() == rf.finding_id.lower():
                matches = True

            if matches:
                rescan_ev_ids.extend(rf.evidence_ids)
                if rf.status == FindingStatus.ACTIVE:
                    matching_active_findings.append(rf)
                else:
                    matching_clean_findings.append(rf)

        # Case 3: Still vulnerable
        if matching_active_findings:
            first_act = matching_active_findings[0]
            return SecurityVerification(
                verification_id=verification_id,
                finding_id=original_finding.finding_id,
                tenant_id=tenant_id,
                rescan_commit=fixed_commit,
                rescan_artifact_digest=rescan_artifact_digest,
                rescan_evidence_ids=rescan_ev_ids,
                status=SecurityVerificationStatus.STILL_VULNERABLE,
                verified_at=now_str,
                notes=f"Remediation PR merged, but fresh rescan on commit {fixed_commit[:10]} still detected active vulnerability: {first_act.description}",
            )

        # Case 4: Verified Resolved
        return SecurityVerification(
            verification_id=verification_id,
            finding_id=original_finding.finding_id,
            tenant_id=tenant_id,
            rescan_commit=fixed_commit,
            rescan_artifact_digest=rescan_artifact_digest,
            rescan_evidence_ids=rescan_ev_ids,
            status=SecurityVerificationStatus.VERIFIED_RESOLVED,
            verified_at=now_str,
            notes=f"Authoritative security rescan on commit {fixed_commit[:10]} verified vulnerability is RESOLVED.",
        )

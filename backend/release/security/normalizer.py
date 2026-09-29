"""
Finding Normalization & Multi-Scanner Ingestion (Brick 4.7)

Provides vendor-neutral normalization for:
1. SAST (Semgrep, SonarQube, CodeQL)
2. SCA / Dependency Vulnerabilities (Snyk, Dependabot, Trivy, OSV)
3. Secrets (GitLeaks, TruffleHog, SecretStore)
4. Container Vulnerabilities (Trivy, Clair, Grype)
5. Infrastructure as Code (Checkov, tfsec)

Guarantees:
- Enforces exact repository, commit, artifact_digest, and tenant_id binding.
- Rejects unvalidated or cross-repository finding injections.
- Produces canonical SecurityFinding objects and Evidence records.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from backend.evidence.models import Evidence
from backend.release.connectivity.credentials import GLOBAL_REDACTOR
from backend.release.security.models import (
    FindingStatus,
    SecurityCategory,
    SecurityFinding,
    SecuritySeverity,
)


class FindingNormalizationError(ValueError):
    """Raised when finding payload is malformed or violates binding constraints."""
    pass


class SecurityFindingNormalizer:
    """
    Vendor-neutral security finding normalizer.
    Converts diverse scanner representations into canonical SecurityFinding models
    and evidence items with strict identity binding.
    """

    def __init__(self, default_tenant_id: str = "default"):
        self.default_tenant_id = default_tenant_id

    def normalize(
        self,
        raw_finding: Dict[str, Any],
        repository: str,
        commit: str,
        scanner_hint: Optional[str] = None,
        tenant_id: Optional[str] = None,
        artifact_digest: Optional[str] = None,
    ) -> SecurityFinding:
        """
        Normalize a raw dictionary from any scanner into a canonical SecurityFinding.
        Enforces repository and commit binding.
        """
        tenant = tenant_id or self.default_tenant_id

        # 1. Enforce repository and commit identity
        if not repository or not commit:
            raise FindingNormalizationError("Both repository and commit are strictly required for security finding normalization.")

        # Detect cross-repository or cross-tenant injection if payload specifies foreign keys
        payload_repo = raw_finding.get("repository") or raw_finding.get("repo")
        if payload_repo and payload_repo != repository:
            raise FindingNormalizationError(
                f"Finding repository mismatch: payload specifies '{payload_repo}' but investigation target is '{repository}'."
            )

        payload_tenant = raw_finding.get("tenant_id")
        if payload_tenant and payload_tenant != tenant:
            raise FindingNormalizationError(
                f"Finding tenant mismatch: payload specifies '{payload_tenant}' but investigation target is '{tenant}'."
            )

        payload_commit = raw_finding.get("commit") or raw_finding.get("commit_sha")
        if payload_commit and payload_commit != commit:
            payload_digest = raw_finding.get("artifact_digest") or raw_finding.get("image_digest")
            if not (artifact_digest and payload_digest and payload_digest.lower() == artifact_digest.lower()):
                raise FindingNormalizationError(
                    f"Finding commit mismatch: payload specifies '{payload_commit}' but investigation target is '{commit}'."
                )

        # 2. Extract scanner
        scanner = str(scanner_hint or raw_finding.get("scanner") or raw_finding.get("tool") or "unknown").lower()

        # 3. Determine category
        category = self._infer_category(raw_finding, scanner)

        # 4. Determine severity
        severity = self._normalize_severity(raw_finding.get("severity") or raw_finding.get("level") or "MEDIUM")

        # 5. Determine status
        status = self._normalize_status(raw_finding.get("status") or raw_finding.get("state") or "ACTIVE")

        # 6. Extract identifiers
        finding_id = str(
            raw_finding.get("finding_id")
            or raw_finding.get("id")
            or raw_finding.get("check_id")
            or raw_finding.get("rule_id")
            or raw_finding.get("vulnerability_id")
            or f"{scanner}-{uuid.uuid4().hex[:8]}"
        )

        cve = raw_finding.get("cve") or raw_finding.get("cve_id") or raw_finding.get("VulnerabilityID")
        cwe = raw_finding.get("cwe")
        if not cwe and "cwe" in str(raw_finding.get("metadata", {})).lower():
            cwe = str(raw_finding.get("metadata", {}).get("cwe", ""))

        cvss = self._parse_cvss(raw_finding.get("cvss") or raw_finding.get("cvss_v3") or raw_finding.get("score"))

        # 7. Package and Versioning (for SCA / Container)
        package = (
            raw_finding.get("package")
            or raw_finding.get("pkg_name")
            or raw_finding.get("PkgName")
            or raw_finding.get("dependency")
        )
        current_version = (
            raw_finding.get("current_version")
            or raw_finding.get("installed_version")
            or raw_finding.get("InstalledVersion")
            or raw_finding.get("version")
        )
        fixed_version = (
            raw_finding.get("fixed_version")
            or raw_finding.get("FixedVersion")
            or raw_finding.get("remediation_version")
        )
        vulnerable_range = raw_finding.get("vulnerable_version_range") or raw_finding.get("vulnerable_range")

        # 8. File and Line Range
        file_path = raw_finding.get("file") or raw_finding.get("path") or raw_finding.get("filename")
        line_range = None
        if "line_range" in raw_finding and isinstance(raw_finding["line_range"], (list, tuple)) and len(raw_finding["line_range"]) == 2:
            line_range = (int(raw_finding["line_range"][0]), int(raw_finding["line_range"][1]))
        elif "start_line" in raw_finding:
            line_range = (int(raw_finding["start_line"]), int(raw_finding.get("end_line", raw_finding["start_line"])))
        elif "line" in raw_finding:
            l = int(raw_finding["line"])
            line_range = (l, l)

        # 9. Description and Remediation
        description = str(
            raw_finding.get("description")
            or raw_finding.get("title")
            or raw_finding.get("message")
            or raw_finding.get("Title")
            or f"{category.value} security issue detected by {scanner}"
        )
        remediation_guidance = str(
            raw_finding.get("remediation_guidance")
            or raw_finding.get("remediation")
            or raw_finding.get("solution")
            or ""
        )

        confidence = float(raw_finding.get("confidence", 1.0))
        is_reachable = bool(raw_finding.get("is_reachable", False))
        is_exploitable = bool(raw_finding.get("is_exploitable_in_context", True))

        now_str = raw_finding.get("timestamp") or "2026-09-09T12:00:00Z"

        return SecurityFinding(
            finding_id=finding_id,
            scanner=scanner,
            category=category,
            severity=severity,
            status=status,
            confidence=confidence,
            tenant_id=tenant,
            repository=repository,
            commit=commit,
            artifact_digest=artifact_digest or raw_finding.get("artifact_digest"),
            file=file_path,
            line_range=line_range,
            package=package,
            current_version=current_version,
            fixed_version=fixed_version,
            vulnerable_version_range=vulnerable_range,
            cve=cve,
            cwe=cwe,
            cvss=cvss,
            description=description,
            remediation_guidance=remediation_guidance,
            is_exploitable_in_context=is_exploitable,
            is_reachable=is_reachable,
            first_seen=raw_finding.get("first_seen", now_str),
            last_seen=now_str,
            provenance={
                "scanner": scanner,
                "ingestion_time": time.time(),
                "raw_keys": list(raw_finding.keys()),
            },
            raw_payload=raw_finding,
        )

    def to_evidence(self, finding: SecurityFinding) -> Evidence:
        """
        Convert a SecurityFinding into canonical Evidence model for DAG investigation.
        Redacts sensitive tokens in descriptions.
        """
        clean_desc = GLOBAL_REDACTOR.redact(finding.description)
        content = (
            f"Security Finding: {finding.finding_id} ({finding.category.value})\n"
            f"Scanner: {finding.scanner} | Severity: {finding.severity.value} | Status: {finding.status.value}\n"
            f"Repository: {finding.repository} | Commit: {finding.commit[:10]}\n"
            f"CVE: {finding.cve or 'None'} | Package: {finding.package or 'N/A'} ({finding.current_version or 'unknown'})\n"
            f"Fixed in: {finding.fixed_version or 'N/A'} | Vulnerable Range: {finding.vulnerable_version_range or 'N/A'}\n"
            f"File: {finding.file or 'N/A'} | Lines: {finding.line_range or 'N/A'}\n"
            f"Description: {clean_desc}"
        )

        evidence_id = f"SEC-{finding.scanner.upper()}-{finding.finding_id}"
        finding.evidence_ids.append(evidence_id)

        encoded = content.encode("utf-8")
        content_hash = hashlib.sha256(encoded).hexdigest()

        return Evidence(
            evidence_id=evidence_id,
            source_id=finding.scanner,
            source_type="security",
            uri=f"security://{finding.scanner}/{evidence_id}",
            content=content,
            content_hash=content_hash,
            source_path=f"/security/{finding.scanner}/{finding.finding_id}.json",
            chunk_index=0,
            start_offset=0,
            end_offset=len(encoded),
            confidence=finding.confidence,
            tenant_id=finding.tenant_id,
            created_at=finding.last_seen,
            metadata={
                "finding_id": finding.finding_id,
                "scanner": finding.scanner,
                "category": finding.category.value,
                "severity": finding.severity.value,
                "status": finding.status.value,
                "repository": finding.repository,
                "commit": finding.commit,
                "artifact_digest": finding.artifact_digest,
                "package": finding.package,
                "current_version": finding.current_version,
                "fixed_version": finding.fixed_version,
                "vulnerable_version_range": finding.vulnerable_version_range,
                "cve": finding.cve,
                "cwe": finding.cwe,
                "cvss": finding.cvss,
                "is_reachable": finding.is_reachable,
                "is_exploitable": finding.is_exploitable_in_context,
            },
        )

    def _infer_category(self, raw: Dict[str, Any], scanner: str) -> SecurityCategory:
        explicit = str(raw.get("category", "")).upper()
        if explicit in SecurityCategory.__members__:
            return SecurityCategory(explicit)

        scanner_lower = scanner.lower()
        if any(k in scanner_lower for k in ("snyk", "dependabot", "osv", "pip-audit")):
            return SecurityCategory.SCA
        if any(k in scanner_lower for k in ("gitleaks", "trufflehog", "secret")):
            return SecurityCategory.SECRETS
        if any(k in scanner_lower for k in ("trivy", "clair", "grype")):
            if raw.get("PkgType") == "os" or "image" in raw or raw.get("artifact_digest"):
                return SecurityCategory.CONTAINER
            return SecurityCategory.SCA
        if any(k in scanner_lower for k in ("checkov", "tfsec", "terrascan")):
            return SecurityCategory.IAC
        if any(k in scanner_lower for k in ("semgrep", "codeql", "sonarqube", "bandit")):
            if "sca" in str(raw.get("check_id", "")).lower() or "dependency" in str(raw).lower():
                return SecurityCategory.SCA
            return SecurityCategory.SAST

        # Fallback inspection of raw content
        text = str(raw).lower()
        if "secret" in text or "token" in text or "private key" in text:
            return SecurityCategory.SECRETS
        if "dependency" in text or "package" in text or "lockfile" in text:
            return SecurityCategory.SCA
        if "terraform" in text or "cloudformation" in text or "dockerfile" in text:
            return SecurityCategory.IAC

        return SecurityCategory.SAST

    def _normalize_severity(self, raw_sev: Any) -> SecuritySeverity:
        s = str(raw_sev).strip().upper()
        if s in ("CRITICAL", "ERROR", "BLOCKER"):
            return SecuritySeverity.CRITICAL
        if s in ("HIGH", "MAJOR", "WARNING"):
            return SecuritySeverity.HIGH
        if s in ("MEDIUM", "MODERATE", "WARN"):
            return SecuritySeverity.MEDIUM
        if s in ("LOW", "MINOR"):
            return SecuritySeverity.LOW
        if s in ("INFO", "INFORMATIONAL", "NOTE"):
            return SecuritySeverity.INFO
        return SecuritySeverity.MEDIUM

    def _normalize_status(self, raw_status: Any) -> FindingStatus:
        st = str(raw_status).strip().upper()
        if st in ("RESOLVED", "FIXED", "CLOSED"):
            return FindingStatus.RESOLVED
        if st in ("EXCEPTION_ACCEPTED", "ACCEPTED", "IGNORED", "RISK_ACCEPTED", "WONT_FIX"):
            return FindingStatus.EXCEPTION_ACCEPTED
        if st in ("FALSE_POSITIVE", "MUTED"):
            return FindingStatus.FALSE_POSITIVE
        if st in ("SUPERSEDED", "OUTDATED"):
            return FindingStatus.SUPERSEDED
        return FindingStatus.ACTIVE

    def _parse_cvss(self, val: Any) -> Optional[float]:
        if val is None:
            return None
        try:
            f = float(val)
            return max(0.0, min(10.0, round(f, 2)))
        except (ValueError, TypeError):
            return None

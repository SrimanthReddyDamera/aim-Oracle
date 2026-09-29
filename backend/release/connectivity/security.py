"""
Production Security Scanner Providers (Brick 4.1)

Connects to Semgrep (SAST/SCA) and Trivy (Container/Vulnerability) APIs/SARIF:
1. Resilient HTTP transport (circuit breaker, retries, rate-limits)
2. Token-based authentication via CredentialProvider
3. Normalizes findings into canonical SecurityFinding models (CWE, CVE, CVSS, reachability)
4. Normalizes findings into canonical Evidence without hardcoding blocking behavior
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import httpx

from backend.evidence.models import Evidence
from backend.release.connectivity.credentials import CredentialProvider, EnvCredentialProvider, GLOBAL_REDACTOR
from backend.release.connectivity.github import _parse_repo_slug
from backend.release.connectivity.resilience import ResilientHttpClient
from backend.release.models import (
    FindingStatus,
    ReleaseCandidate,
    SecurityCategory,
    SecurityFinding,
    SecuritySeverity,
)
from backend.release.providers import SecurityScanProvider, _create_evidence


class SemgrepSecurityProvider(SecurityScanProvider):
    """
    Production-quality Semgrep Security Provider.
    Supports querying Semgrep Cloud / Network REST API and parsing SARIF/Semgrep JSON findings.
    """

    def __init__(
        self,
        credential_provider: Optional[CredentialProvider] = None,
        base_url: str = "https://semgrep.dev/api/v1",
        client: Optional[ResilientHttpClient] = None,
        transport: Optional[httpx.BaseTransport] = None,
    ):
        self.credential_provider = credential_provider or EnvCredentialProvider()
        self.base_url = base_url.rstrip("/")
        self.client = client or ResilientHttpClient(
            provider_id="semgrep",
            base_url=self.base_url,
            transport=transport,
        )

    def _get_auth_headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "User-Agent": "ORACLE-Intelligence-Engine/4.1",
        }
        token = self.credential_provider.get_token("semgrep")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def get_findings_for_commit(self, repository: str, commit: str) -> List[SecurityFinding]:
        """Fetch static security and supply-chain findings for commit from Semgrep API."""
        owner, repo_name = _parse_repo_slug(repository)
        headers = self._get_auth_headers()
        url = "/deployments/findings"
        params = {"repo": f"{owner}/{repo_name}", "commit": commit}

        resp = self.client.request("GET", url, headers=headers, params=params)
        if resp.status_code != 200:
            return []

        findings_data = resp.json().get("findings", [])
        return self._parse_semgrep_findings(findings_data, repository, commit)

    def _parse_semgrep_findings(
        self,
        raw_findings: List[Dict[str, Any]],
        repository: str,
        commit: str,
    ) -> List[SecurityFinding]:
        """Normalize raw Semgrep findings into canonical SecurityFinding instances."""
        normalized: List[SecurityFinding] = []

        for f in raw_findings:
            fid = str(f.get("id") or f.get("check_id") or "SEMGREP-VULN")
            rule_id = f.get("check_id") or fid
            extra = f.get("extra", {})
            metadata = extra.get("metadata", {})

            # Severity mapping
            raw_sev = str(extra.get("severity") or metadata.get("severity", "MEDIUM")).upper()
            if raw_sev in ("ERROR", "CRITICAL"):
                severity = SecuritySeverity.CRITICAL
            elif raw_sev in ("WARNING", "HIGH"):
                severity = SecuritySeverity.HIGH
            elif raw_sev == "LOW":
                severity = SecuritySeverity.LOW
            else:
                severity = SecuritySeverity.MEDIUM

            # Category mapping (SAST vs SCA vs SECRETS)
            is_sca = "sca" in rule_id.lower() or "dependency" in rule_id.lower() or "package" in metadata
            is_secrets = "secret" in rule_id.lower() or "token" in rule_id.lower()
            if is_sca:
                category = SecurityCategory.SCA
            elif is_secrets:
                category = SecurityCategory.SECRETS
            else:
                category = SecurityCategory.SAST

            # Triage state
            triage_state = str(f.get("state") or f.get("triage_state", "ACTIVE")).upper()
            if triage_state in ("RESOLVED", "FIXED"):
                status = FindingStatus.RESOLVED
            elif triage_state in ("IGNORED", "ACCEPTED", "EXCEPTION_ACCEPTED"):
                status = FindingStatus.EXCEPTION_ACCEPTED
            elif triage_state in ("FALSE_POSITIVE", "MUTED"):
                status = FindingStatus.FALSE_POSITIVE
            else:
                status = FindingStatus.ACTIVE

            # Reachability
            is_reachable = extra.get("is_reachable", metadata.get("reachable", True))
            is_exploitable = extra.get("is_exploitable", True)

            # Location
            filepath = f.get("path")
            start_line = f.get("start", {}).get("line", 1) if isinstance(f.get("start"), dict) else 1
            end_line = f.get("end", {}).get("line", 1) if isinstance(f.get("end"), dict) else start_line

            # Package & version info if SCA
            package_name = metadata.get("package") or extra.get("package_name")
            current_ver = metadata.get("current_version") or extra.get("current_version")
            fixed_ver = metadata.get("fixed_version") or extra.get("fixed_version")
            cve = metadata.get("cve") or extra.get("cve")
            cwe = metadata.get("cwe")

            cwe_str = str(cwe[0]) if isinstance(cwe, list) and cwe else str(cwe) if cwe else None

            normalized.append(
                SecurityFinding(
                    finding_id=fid,
                    scanner="semgrep",
                    category=category,
                    severity=severity,
                    status=status,
                    repository=repository,
                    commit=commit,
                    file=filepath,
                    line_range=(start_line, end_line),
                    package=package_name,
                    current_version=current_ver,
                    fixed_version=fixed_ver,
                    cve=cve,
                    cwe=cwe_str,
                    description=extra.get("message") or f.get("description") or rule_id,
                    remediation_guidance=extra.get("fix") or metadata.get("remediation", ""),
                    is_reachable=is_reachable,
                    is_exploitable_in_context=is_exploitable,
                    first_seen=f.get("created_at", ""),
                    last_seen=f.get("updated_at", ""),
                    provenance={"scanner": "semgrep", "rule_id": rule_id},
                )
            )

        return normalized

    def fetch_evidence_for_release(self, candidate: ReleaseCandidate) -> List[Evidence]:
        """Aggregate Semgrep security findings into canonical Evidence."""
        evidence_list: List[Evidence] = []
        findings = self.get_findings_for_commit(candidate.repository, candidate.commit)

        for f in findings:
            pkg_clause = (
                f"Package {f.package} ({f.current_version}) -> Fixed in: {f.fixed_version or 'None'}."
                if f.package
                else ""
            )
            reach_clause = (
                "Vulnerable code path is REACHABLE."
                if f.is_reachable
                else "Code path is UNREACHABLE."
            )
            cve_clause = (
                f"Vulnerability: {f.cve} (CVSS {f.cvss or 'N/A'}, CWE {f.cwe or 'N/A'})."
                if f.cve
                else ""
            )
            raw_content = (
                f"Security Finding {f.finding_id} from {f.scanner} on {f.repository} commit {f.commit[:10]}:\n"
                f"Category: {f.category.value}. Severity: {f.severity.value}. Status: {f.status.value}.\n"
                f"{cve_clause}\n"
                f"{pkg_clause}\n"
                f"{reach_clause}\n"
                f"Description: {f.description}.\n"
                f"Remediation: {f.remediation_guidance}."
            )
            clean_content = GLOBAL_REDACTOR.redact(raw_content)

            evidence_list.append(
                _create_evidence(
                    evidence_id=f"SEC-{f.scanner}-{f.finding_id}",
                    source_id=f.scanner,
                    source_type="security",
                    content=clean_content,
                    metadata={
                        "finding_id": f.finding_id,
                        "scanner": f.scanner,
                        "category": f.category.value,
                        "severity": f.severity.value,
                        "status": f.status.value,
                        "cve": f.cve,
                        "commit": f.commit,
                        "package": f.package,
                        "current_version": f.current_version,
                        "fixed_version": f.fixed_version,
                        "is_reachable": f.is_reachable,
                        "is_exploitable": f.is_exploitable_in_context,
                    },
                    timestamp=f.last_seen or candidate.created_at,
                )
            )

        return evidence_list


class TrivySecurityProvider(SecurityScanProvider):
    """
    Production-quality Trivy Container & Vulnerability Provider.
    Queries Trivy vulnerability server or parses Trivy JSON/SARIF output.
    """

    def __init__(
        self,
        credential_provider: Optional[CredentialProvider] = None,
        base_url: str = "http://localhost:4954",
        client: Optional[ResilientHttpClient] = None,
        transport: Optional[httpx.BaseTransport] = None,
    ):
        self.credential_provider = credential_provider or EnvCredentialProvider()
        self.base_url = base_url.rstrip("/")
        self.client = client or ResilientHttpClient(
            provider_id="trivy",
            base_url=self.base_url,
            transport=transport,
        )

    def get_findings_for_commit(self, repository: str, commit: str) -> List[SecurityFinding]:
        """Fetch container / vulnerability scan results from Trivy server."""
        headers = {"Accept": "application/json"}
        token = self.credential_provider.get_token("trivy")
        if token:
            headers["Trivy-Token"] = token

        resp = self.client.request("GET", f"/v1/scan?commit={commit}&repo={repository}", headers=headers)
        if resp.status_code != 200:
            return []

        results = resp.json().get("Results", [])
        findings: List[SecurityFinding] = []

        for target in results:
            vulns = target.get("Vulnerabilities", [])
            for v in vulns:
                raw_sev = str(v.get("Severity", "MEDIUM")).upper()
                sev = (
                    SecuritySeverity.CRITICAL if raw_sev == "CRITICAL"
                    else SecuritySeverity.HIGH if raw_sev == "HIGH"
                    else SecuritySeverity.LOW if raw_sev == "LOW"
                    else SecuritySeverity.MEDIUM
                )
                findings.append(
                    SecurityFinding(
                        finding_id=str(v.get("VulnerabilityID", "TRIVY-VULN")),
                        scanner="trivy",
                        category=SecurityCategory.CONTAINER,
                        severity=sev,
                        status=FindingStatus.ACTIVE,
                        repository=repository,
                        commit=commit,
                        package=v.get("PkgName"),
                        current_version=v.get("InstalledVersion"),
                        fixed_version=v.get("FixedVersion"),
                        cve=v.get("VulnerabilityID"),
                        description=v.get("Title") or v.get("Description", "Container vulnerability"),
                    )
                )

        return findings

    def fetch_evidence_for_release(self, candidate: ReleaseCandidate) -> List[Evidence]:
        findings = self.get_findings_for_commit(candidate.repository, candidate.commit)
        evidence_list = []
        for f in findings:
            raw_content = (
                f"Security Finding {f.finding_id} from {f.scanner} on {f.repository} commit {f.commit[:10]}:\n"
                f"Category: {f.category.value}. Severity: {f.severity.value}. Status: {f.status.value}.\n"
                f"Vulnerability: {f.cve}.\n"
                f"Package: {f.package} ({f.current_version}) -> Fixed: {f.fixed_version}.\n"
                f"Description: {f.description}."
            )
            evidence_list.append(
                _create_evidence(
                    evidence_id=f"SEC-{f.scanner}-{f.finding_id}",
                    source_id=f.scanner,
                    source_type="security",
                    content=GLOBAL_REDACTOR.redact(raw_content),
                    metadata={
                        "finding_id": f.finding_id,
                        "scanner": f.scanner,
                        "category": f.category.value,
                        "severity": f.severity.value,
                        "status": f.status.value,
                        "cve": f.cve,
                        "commit": f.commit,
                        "package": f.package,
                        "current_version": f.current_version,
                        "fixed_version": f.fixed_version,
                    },
                )
            )
        return evidence_list

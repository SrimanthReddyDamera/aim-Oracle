"""
Guardrailed Advisory LLM Boundary (Brick 4.7)

Enforces strict controller sovereignty and advisory-only LLM scope:
Allowed LLM Functions:
- Explain security findings and CVE mechanics in human-readable terms
- Propose hypotheses regarding vulnerability origin
- Suggest investigation gaps or queries
- Suggest candidate remediations and workarounds
- Summarize verified evidence

Prohibited Actions (Hard-Fail / Blocked by Guardrail):
- Mark vulnerabilities resolved
- Approve security clearance
- Override deterministic policy
- Invent confirmed reachability
- Select authoritative evidence
- Suppress contradictions
- Mutate finding records or database states
- Bypass required rescan verification
- Authorize deployment

CRITICAL INVARIANT:
- Controller sovereignty is absolute.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.release.security.models import (
    ReachabilityAssessment,
    SecurityDecision,
    SecurityDecisionOutcome,
    SecurityFinding,
)


class SecuritySovereigntyViolation(PermissionError):
    """Raised when an advisory LLM or untrusted agent attempts to violate controller sovereignty."""
    pass


class AdvisoryExplanation(BaseModel):
    """Safe, advisory explanation for human operators."""
    finding_id: str
    summary: str
    hypothetical_impact: str
    suggested_investigation_steps: List[str] = Field(default_factory=list)
    suggested_remediation: str = ""
    disclaimer: str = "ADVISORY ONLY: Controller maintains sole authority over security decisions and verification."


class SecurityAdvisoryExplainer:
    """
    Guardrailed security advisory assistant.
    Provides natural language explanations and hypotheses without authority to mutate findings
    or alter decision outcomes.
    """

    def __init__(self):
        # Disallowed tokens/commands attempting to override sovereign controller
        self.forbidden_mutation_patterns = [
            re.compile(r"\bmark\s+(?:as\s+)?resolved\b", re.IGNORECASE),
            re.compile(r"\bapprove\s+(?:deployment|clearance|security)\b", re.IGNORECASE),
            re.compile(r"\boverride\s+(?:policy|blocker|decision)\b", re.IGNORECASE),
            re.compile(r"\bdeclare\s+(?:clean|safe|resolved)\b", re.IGNORECASE),
            re.compile(r"\bbypass\s+(?:verification|rescan)\b", re.IGNORECASE),
            re.compile(r"\bsuppress\s+contradiction\b", re.IGNORECASE),
        ]

    def explain_finding(
        self,
        finding: SecurityFinding,
        reachability: Optional[ReachabilityAssessment] = None,
    ) -> AdvisoryExplanation:
        """
        Generate advisory explanation for human operators.
        """
        pkg = finding.package or "the target component"
        cve = finding.cve or finding.finding_id

        summary = (
            f"Vulnerability {cve} ({finding.severity.value}) in {pkg}: "
            f"{finding.description.strip()}"
        )

        impact = (
            f"If exploitable, an attacker could leverage this {finding.category.value} issue via {pkg}. "
            f"Current verified reachability status is {reachability.status.value if reachability else 'UNKNOWN'}."
        )

        steps = [
            f"Review import references to {pkg} across application routes",
            "Verify whether user-controlled input reaches vulnerable arguments",
            "Inspect upstream lockfile for available security patches",
        ]

        rem_sugg = finding.remediation_guidance or f"Upgrade {pkg} to fixed version {finding.fixed_version or 'latest'}."

        return AdvisoryExplanation(
            finding_id=finding.finding_id,
            summary=summary,
            hypothetical_impact=impact,
            suggested_investigation_steps=steps,
            suggested_remediation=rem_sugg,
        )

    def validate_advisory_input(self, text: str) -> None:
        """
        Validate that input from external agent/LLM does not attempt to execute
        unauthorized state mutations or prompt injections against the controller.
        """
        for pat in self.forbidden_mutation_patterns:
            if pat.search(text):
                raise SecuritySovereigntyViolation(
                    f"Advisory agent attempted forbidden controller action matching '{pat.pattern}'. "
                    "LLM agents are strictly advisory and cannot alter security outcomes."
                )

    def sanitize_untrusted_prompt(self, raw_input: str) -> str:
        """Strip dangerous delimiter or prompt injection artifacts."""
        cleaned = re.sub(r"(?:<\|im_start\|>|<\|im_end\|>|\[SYSTEM_OVERRIDE\]|IGNORE PREVIOUS INSTRUCTIONS)", "[REDACTED_PROMPT_INJECTION]", raw_input, flags=re.IGNORECASE)
        return cleaned

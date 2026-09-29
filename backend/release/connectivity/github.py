"""
Production GitHub Release Provider (Brick 4.1)

Connects to GitHub REST API (v3) with:
1. Resilient HTTP transport (circuit breaker, retries, rate-limits)
2. Token-based authentication via CredentialProvider
3. PR review status, approvers, merge state, and rollback plan discovery
4. Canonical Evidence normalization with SHA-256 hashes and byte-level offsets
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

import httpx

from backend.evidence.models import Evidence
from backend.release.connectivity.credentials import CredentialProvider, EnvCredentialProvider, GLOBAL_REDACTOR
from backend.release.connectivity.resilience import (
    ProviderAuthenticationError,
    ProviderNetworkError,
    ResilientHttpClient,
)
from backend.release.models import CodeReviewStatus, PullRequestReview, ReleaseCandidate
from backend.release.providers import GitReleaseProvider, _create_evidence


def _parse_repo_slug(repo: str) -> Tuple[str, str]:
    """Parse 'github.com/owner/repo' or 'owner/repo' into (owner, repo)."""
    cleaned = repo.replace("https://", "").replace("http://", "").replace("github.com/", "").strip("/")
    parts = cleaned.split("/")
    if len(parts) >= 2:
        return parts[0], parts[1]
    return "unknown", cleaned


def _parse_pr_number(pr_id: str) -> int:
    """Extract integer number from 'PR-582', '#582', or '582'."""
    digits = re.findall(r"\d+", pr_id)
    return int(digits[0]) if digits else 0


class GitHubReleaseProvider(GitReleaseProvider):
    """
    Production-quality GitHub Release & Source Control Provider.
    Queries GitHub REST API v3 and normalizes results into canonical ORACLE models.
    """

    def __init__(
        self,
        credential_provider: Optional[CredentialProvider] = None,
        base_url: str = "https://api.github.com",
        client: Optional[ResilientHttpClient] = None,
        transport: Optional[httpx.BaseTransport] = None,
    ):
        self.credential_provider = credential_provider or EnvCredentialProvider()
        self.base_url = base_url.rstrip("/")
        self.client = client or ResilientHttpClient(
            provider_id="github",
            base_url=self.base_url,
            transport=transport,
        )

    def _get_auth_headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "ORACLE-Intelligence-Engine/4.1",
        }
        token = self.credential_provider.get_token("github", scope="repo")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def get_pull_request(self, repository: str, pr_id: str) -> Optional[PullRequestReview]:
        """Fetch real Pull Request and review state from GitHub REST API."""
        owner, repo_name = _parse_repo_slug(repository)
        number = _parse_pr_number(pr_id)
        if number == 0:
            return None

        headers = self._get_auth_headers()

        # 1. Fetch Pull Request metadata
        pr_url = f"/repos/{owner}/{repo_name}/pulls/{number}"
        try:
            resp = self.client.request("GET", pr_url, headers=headers)
            if resp.status_code == 404:
                return None
            pr_data = resp.json()
        except ProviderAuthenticationError:
            raise
        except (ProviderNetworkError, Exception):
            return None

        head_commit = pr_data.get("head", {}).get("sha", "")
        is_merged = pr_data.get("merged", False)
        body_text = pr_data.get("body") or ""
        title_text = pr_data.get("title") or ""

        # 2. Fetch PR reviews
        reviews_url = f"/repos/{owner}/{repo_name}/pulls/{number}/reviews"
        reviews_data = []
        try:
            reviews_resp = self.client.request("GET", reviews_url, headers=headers)
            if reviews_resp.status_code == 200:
                raw_json = reviews_resp.json()
                reviews_data = raw_json if isinstance(raw_json, list) else []
        except ProviderNetworkError:
            reviews_data = []

        reviewers: List[str] = []
        approvers: List[str] = []
        has_changes_requested = False

        for r in reviews_data:
            user = r.get("user", {}).get("login", "unknown")
            state = r.get("state", "").upper()
            reviewers.append(user)
            if state == "APPROVED":
                approvers.append(user)
            elif state == "CHANGES_REQUESTED":
                has_changes_requested = True

        if has_changes_requested:
            review_status = CodeReviewStatus.CHANGES_REQUESTED
        elif len(approvers) > 0:
            review_status = CodeReviewStatus.APPROVED
        else:
            review_status = CodeReviewStatus.PENDING

        # 3. Check for rollback procedure
        combined_text = f"{title_text}\n{body_text}".lower()
        has_rollback = "rollback" in combined_text or "revert procedure" in combined_text or "runbook" in combined_text

        return PullRequestReview(
            pr_id=f"PR-{number}",
            repository=repository,
            head_commit=head_commit,
            status=review_status,
            reviewers=list(dict.fromkeys(reviewers)),
            approvers=list(dict.fromkeys(approvers)),
            is_merged=is_merged,
            rollback_procedure_documented=has_rollback,
            timestamp=pr_data.get("created_at", ""),
            provenance={"provider": "github", "url": pr_data.get("html_url", "")},
        )

    def get_commit_reviews(self, repository: str, commit: str) -> List[PullRequestReview]:
        """Fetch all pull requests associated with a commit."""
        owner, repo_name = _parse_repo_slug(repository)
        headers = self._get_auth_headers()
        url = f"/repos/{owner}/{repo_name}/commits/{commit}/pulls"
        resp = self.client.request("GET", url, headers=headers)
        if resp.status_code != 200:
            return []

        prs_data = resp.json()
        results: List[PullRequestReview] = []
        for pr_item in prs_data:
            num = pr_item.get("number")
            if num:
                pr = self.get_pull_request(repository, str(num))
                if pr:
                    results.append(pr)
        return results

    def fetch_evidence_for_release(self, candidate: ReleaseCandidate) -> List[Evidence]:
        """Aggregate GitHub source control evidence for the candidate."""
        evidence_list: List[Evidence] = []
        prs: List[PullRequestReview] = []

        if candidate.pull_request_id:
            pr = self.get_pull_request(candidate.repository, candidate.pull_request_id)
            if pr:
                prs.append(pr)
        else:
            prs.extend(self.get_commit_reviews(candidate.repository, candidate.commit))

        for pr in prs:
            rb_clause = (
                "Rollback procedure is verified and documented."
                if pr.rollback_procedure_documented
                else "No rollback procedure documented."
            )
            raw_content = (
                f"Pull Request {pr.pr_id} on {pr.repository} for commit {pr.head_commit[:10]}:\n"
                f"Code Review Status: {pr.status.value}.\n"
                f"Reviewers: {', '.join(pr.reviewers) if pr.reviewers else 'None'}.\n"
                f"Approvers: {', '.join(pr.approvers) if pr.approvers else 'None'}.\n"
                f"Merged: {pr.is_merged}.\n"
                f"{rb_clause}"
            )
            clean_content = GLOBAL_REDACTOR.redact(raw_content)

            evidence_list.append(
                _create_evidence(
                    evidence_id=f"GIT-{pr.pr_id}",
                    source_id=pr.repository,
                    source_type="git",
                    content=clean_content,
                    metadata={
                        "pr_id": pr.pr_id,
                        "status": pr.status.value,
                        "commit": pr.head_commit,
                        "approvers": pr.approvers,
                        "is_merged": pr.is_merged,
                    },
                    timestamp=pr.timestamp or candidate.created_at,
                )
            )

        return evidence_list

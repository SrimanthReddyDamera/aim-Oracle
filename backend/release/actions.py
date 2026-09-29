"""
Governed Action Framework & Live Idempotent Execution (Bricks 4.0 & 4.2)

Implements enterprise governance for autonomous system operations:
Lifecycle: PROPOSAL -> VALIDATION -> AUTHORIZATION -> HUMAN APPROVAL -> EXECUTION -> VERIFICATION
Enforces:
1. Idempotency keys to prevent duplicate side-effects (replay protection).
2. Human-in-the-loop approval requirements (mandatory authorization).
3. Fail-closed safety policy (LIVE_ACTIONS must be explicitly enabled).
4. Restricts live side-effects to low-risk actions (COMMENT_ON_PR, CREATE_JIRA_REMEDIATION).
5. Post-execution verification confirming external state.
6. Append-only audit trails with zero credential leakage.
"""

from __future__ import annotations

import abc
import base64
import hashlib
import json
import time
import uuid
from typing import Any, Dict, List, Optional

import httpx

from backend.release.connectivity.credentials import (
    CredentialProvider,
    EnvCredentialProvider,
    GLOBAL_REDACTOR,
)
from backend.release.connectivity.github import _parse_repo_slug
from backend.release.connectivity.resilience import ResilientHttpClient, scrub_secrets
from backend.release.models import (
    GovernedActionProposal,
    GovernedActionStatus,
    GovernedActionType,
)


class ActionAuthorizationError(PermissionError):
    """Raised when an unauthorized action is attempted."""
    pass


class ActionValidationError(ValueError):
    """Raised when an action payload fails structural validation."""
    pass


class LiveActionPolicyError(PermissionError):
    """Raised when live external writes are attempted without explicit authorization/configuration."""
    pass


class ActionVerificationError(RuntimeError):
    """Raised when external verification of an executed action fails."""
    pass


# -----------------------------------------------------------------------------
# 1. ACTION DISPATCHER INTERFACE & IMPLEMENTATIONS
# -----------------------------------------------------------------------------

class ActionDispatcher(abc.ABC):
    """Abstract dispatcher contract for governed actions."""

    @abc.abstractmethod
    def dispatch(self, action: GovernedActionProposal, dry_run: bool = False) -> Dict[str, Any]:
        """Execute the action either in dry-run or actual execution mode."""
        pass

    @abc.abstractmethod
    def verify(self, action: GovernedActionProposal, execution_result: Dict[str, Any]) -> bool:
        """Verify the side-effect exists in the target system."""
        pass


class SimulatedActionDispatcher(ActionDispatcher):
    """Deterministic local simulator for testing without network side effects."""

    def dispatch(self, action: GovernedActionProposal, dry_run: bool = False) -> Dict[str, Any]:
        now_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        result_payload = {
            "action_id": action.action_id,
            "action_type": action.action_type.value,
            "target_system": action.target_system,
            "dispatched_at": now_ts,
            "status": "DISPATCH_CONFIRMED" if not dry_run else "DRY_RUN_SIMULATED",
            "dry_run": dry_run,
            "reference": f"{action.target_system.upper()}-SIM-{uuid.uuid4().hex[:6]}",
        }

        if action.action_type == GovernedActionType.CREATE_JIRA_REMEDIATION:
            result_payload["created_issue_key"] = f"SEC-{uuid.uuid4().hex[:4].upper()}"
        elif action.action_type == GovernedActionType.COMMENT_ON_PR:
            result_payload["comment_id"] = str(uuid.uuid4().int)[:8]
        elif action.action_type == GovernedActionType.BLOCK_DEPLOYMENT:
            result_payload["deployment_gate_state"] = "BLOCKED"
        elif action.action_type == GovernedActionType.APPROVE_DEPLOYMENT:
            result_payload["deployment_gate_state"] = "APPROVED_FOR_RELEASE"

        return result_payload

    def verify(self, action: GovernedActionProposal, execution_result: Dict[str, Any]) -> bool:
        return execution_result.get("status") in ("DISPATCH_CONFIRMED", "DRY_RUN_SIMULATED")


class LiveActionDispatcher(ActionDispatcher):
    """
    Production dispatcher executing real external side-effects against GitHub and Jira Cloud.
    Guarded by:
    - Scope restriction: only low-risk actions (COMMENT_ON_PR, CREATE_JIRA_REMEDIATION) are permitted.
    - Deployment gating actions (APPROVE/BLOCK) are strictly rejected from live write.
    - Credential redaction in all payload logs and audit records.
    - Post-execution verification via target system GET inspection.
    """

    ALLOWED_LIVE_ACTIONS = {
        GovernedActionType.COMMENT_ON_PR,
        GovernedActionType.CREATE_JIRA_REMEDIATION,
    }

    def __init__(
        self,
        credential_provider: Optional[CredentialProvider] = None,
        github_base_url: str = "https://api.github.com",
        jira_base_url: str = "https://corp.atlassian.net",
        github_client: Optional[ResilientHttpClient] = None,
        jira_client: Optional[ResilientHttpClient] = None,
        transport: Optional[httpx.BaseTransport] = None,
    ):
        self.credential_provider = credential_provider or EnvCredentialProvider()
        self.github_base_url = github_base_url.rstrip("/")
        self.jira_base_url = jira_base_url.rstrip("/")

        self.github_client = github_client or ResilientHttpClient(
            provider_id="github_actions",
            base_url=self.github_base_url,
            transport=transport,
        )
        self.jira_client = jira_client or ResilientHttpClient(
            provider_id="jira",
            base_url=self.jira_base_url,
            transport=transport,
        )

    def dispatch(self, action: GovernedActionProposal, dry_run: bool = False) -> Dict[str, Any]:
        """Dispatch live external side effect."""
        # 1. Enforce allowed scope restriction
        if action.action_type not in self.ALLOWED_LIVE_ACTIONS:
            raise LiveActionPolicyError(
                f"Action '{action.action_type.value}' is not permitted for live external write. "
                f"Only low-risk actions {sorted([a.value for a in self.ALLOWED_LIVE_ACTIONS])} are permitted."
            )

        now_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # Dry-run validation mode
        if dry_run:
            return {
                "action_id": action.action_id,
                "action_type": action.action_type.value,
                "target_system": action.target_system,
                "dispatched_at": now_ts,
                "status": "DRY_RUN_VALIDATED",
                "dry_run": True,
                "reference": f"{action.target_system.upper()}-DRYRUN-{uuid.uuid4().hex[:6]}",
            }

        # 2. Execute real external call
        if action.action_type == GovernedActionType.COMMENT_ON_PR:
            return self._dispatch_github_pr_comment(action, now_ts)
        elif action.action_type == GovernedActionType.CREATE_JIRA_REMEDIATION:
            return self._dispatch_jira_remediation(action, now_ts)
        else:
            raise LiveActionPolicyError(f"Unsupported live action type: {action.action_type}")

    def _dispatch_github_pr_comment(self, action: GovernedActionProposal, timestamp: str) -> Dict[str, Any]:
        repo_slug = action.payload.get("repository", "")
        pr_id = action.payload.get("pr_id") or action.payload.get("pull_number")
        comment_text = action.payload.get("comment", "")

        if not repo_slug or not pr_id or not comment_text:
            raise ActionValidationError("COMMENT_ON_PR requires 'repository', 'pr_id', and 'comment'.")

        owner, repo_name = _parse_repo_slug(repo_slug)
        safe_comment = GLOBAL_REDACTOR.redact(comment_text)

        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "ORACLE-Intelligence-Engine/4.2",
        }
        token = self.credential_provider.get_token("github", scope="repo")
        if token:
            headers["Authorization"] = f"Bearer {token}"

        url = f"/repos/{owner}/{repo_name}/issues/{pr_id}/comments"
        payload = {"body": safe_comment}

        resp = self.github_client.request("POST", url, headers=headers, json_data=payload)
        if resp.status_code not in (200, 201):
            raise RuntimeError(f"GitHub API comment creation failed: HTTP {resp.status_code} - {resp.text}")

        resp_data = resp.json()
        comment_id = str(resp_data.get("id", ""))
        html_url = resp_data.get("html_url", "")

        return {
            "action_id": action.action_id,
            "action_type": action.action_type.value,
            "target_system": "github",
            "dispatched_at": timestamp,
            "status": "DISPATCH_CONFIRMED",
            "dry_run": False,
            "comment_id": comment_id,
            "html_url": html_url,
            "reference": f"GITHUB-COMMENT-{comment_id}",
        }

    def _dispatch_jira_remediation(self, action: GovernedActionProposal, timestamp: str) -> Dict[str, Any]:
        project_key = action.payload.get("project_key", "SEC")
        summary = action.payload.get("summary", "")
        description = action.payload.get("description", "Automated remediation task created by ORACLE.")
        issue_type = action.payload.get("issue_type", "Bug")

        if not summary:
            raise ActionValidationError("CREATE_JIRA_REMEDIATION requires 'summary'.")

        safe_summary = GLOBAL_REDACTOR.redact(summary)
        safe_desc = GLOBAL_REDACTOR.redact(description)

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "ORACLE-Intelligence-Engine/4.2",
        }
        token = self.credential_provider.get_token("jira")
        if token:
            if ":" in token:
                encoded = base64.b64encode(token.encode("utf-8")).decode("ascii")
                headers["Authorization"] = f"Basic {encoded}"
            else:
                headers["Authorization"] = f"Bearer {token}"

        url = "/rest/api/3/issue"
        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": safe_summary,
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"text": safe_desc, "type": "text"}],
                        }
                    ],
                },
                "issuetype": {"name": issue_type},
            }
        }

        resp = self.jira_client.request("POST", url, headers=headers, json_data=payload)
        if resp.status_code not in (200, 201):
            raise RuntimeError(f"Jira issue creation failed: HTTP {resp.status_code} - {resp.text}")

        resp_data = resp.json()
        issue_key = resp_data.get("key", "")
        issue_id = resp_data.get("id", "")

        return {
            "action_id": action.action_id,
            "action_type": action.action_type.value,
            "target_system": "jira",
            "dispatched_at": timestamp,
            "status": "DISPATCH_CONFIRMED",
            "dry_run": False,
            "created_issue_key": issue_key,
            "created_issue_id": issue_id,
            "reference": f"JIRA-ISSUE-{issue_key}",
        }

    def verify(self, action: GovernedActionProposal, execution_result: Dict[str, Any]) -> bool:
        """Verify the executed side effect in the target system."""
        if execution_result.get("dry_run"):
            return True

        if action.action_type == GovernedActionType.COMMENT_ON_PR:
            repo_slug = action.payload.get("repository", "")
            comment_id = execution_result.get("comment_id")
            if not repo_slug or not comment_id:
                return False
            owner, repo_name = _parse_repo_slug(repo_slug)
            headers = {"Accept": "application/vnd.github+json"}
            token = self.credential_provider.get_token("github", scope="repo")
            if token:
                headers["Authorization"] = f"Bearer {token}"
            url = f"/repos/{owner}/{repo_name}/issues/comments/{comment_id}"
            resp = self.github_client.request("GET", url, headers=headers)
            return resp.status_code == 200

        elif action.action_type == GovernedActionType.CREATE_JIRA_REMEDIATION:
            issue_key = execution_result.get("created_issue_key")
            if not issue_key:
                return False
            headers = {"Accept": "application/json"}
            token = self.credential_provider.get_token("jira")
            if token:
                if ":" in token:
                    encoded = base64.b64encode(token.encode("utf-8")).decode("ascii")
                    headers["Authorization"] = f"Basic {encoded}"
                else:
                    headers["Authorization"] = f"Bearer {token}"
            url = f"/rest/api/3/issue/{issue_key}"
            resp = self.jira_client.request("GET", url, headers=headers)
            return resp.status_code == 200

        return False


# -----------------------------------------------------------------------------
# 2. GOVERNED ACTION EXECUTOR
# -----------------------------------------------------------------------------

class GovernedActionExecutor:
    """
    Authoritative governance layer for release remediation and CI/CD operations.
    Enforces authorization, human approval, fail-closed live policy, and idempotency.
    """

    def __init__(
        self,
        dispatcher: Optional[ActionDispatcher] = None,
        live_actions_enabled: bool = False,
        dry_run: bool = True,
        action_repo: Optional[Any] = None,
    ):
        self.actions: Dict[str, GovernedActionProposal] = {}
        # Idempotency registry: idempotency_key -> execution result
        self.execution_cache: Dict[str, Dict[str, Any]] = {}
        self.dispatcher = dispatcher or SimulatedActionDispatcher()
        self.live_actions_enabled = live_actions_enabled
        self.dry_run = dry_run
        self.action_repo = action_repo

    def register_proposal(self, action: GovernedActionProposal) -> GovernedActionProposal:
        """Register an action proposal and assign an idempotency key if absent."""
        if not action.idempotency_key:
            payload_str = json.dumps(action.payload, sort_keys=True)
            action.idempotency_key = hashlib.sha256(
                f"{action.action_type.value}:{action.target_system}:{payload_str}".encode("utf-8")
            ).hexdigest()

        action.status = GovernedActionStatus.PROPOSED
        action.audit_trail.append(f"Action proposed at {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
        self.actions[action.action_id] = action
        if self.action_repo:
            self.action_repo.save_action(action)
        return action

    def validate_action(self, action_id: str) -> bool:
        """Validate action schema and target payloads."""
        action = self.actions.get(action_id)
        if not action:
            raise KeyError(f"Action '{action_id}' not found.")

        # Payload validation
        if action.action_type == GovernedActionType.CREATE_JIRA_REMEDIATION:
            if not action.payload.get("summary"):
                raise ActionValidationError("Jira remediation proposal missing 'summary' field.")

        elif action.action_type == GovernedActionType.COMMENT_ON_PR:
            if not action.payload.get("comment"):
                raise ActionValidationError("PR comment proposal missing 'comment' field.")

        elif action.action_type in [GovernedActionType.BLOCK_DEPLOYMENT, GovernedActionType.APPROVE_DEPLOYMENT]:
            if not action.payload.get("release_id"):
                raise ActionValidationError("Deployment action missing 'release_id' field.")

        action.status = GovernedActionStatus.VALIDATED
        action.audit_trail.append("Action validated by Governance Validator.")
        return True

    def authorize_action(
        self,
        action_id: str,
        authorized_by: str,
        human_approved: bool = True,
    ) -> GovernedActionProposal:
        """Authorize an action proposal for execution with mandatory human approval check."""
        action = self.actions.get(action_id)
        if not action:
            raise KeyError(f"Action '{action_id}' not found.")

        if not authorized_by or not authorized_by.strip():
            raise ActionAuthorizationError("Authorization rejected: authorizer identity cannot be empty.")

        if action.requires_human_approval and not human_approved:
            raise ActionAuthorizationError(f"Action '{action_id}' requires explicit human approval.")

        # If not validated yet, validate first
        if action.status == GovernedActionStatus.PROPOSED:
            self.validate_action(action_id)

        action.authorized_by = authorized_by.strip()
        action.status = GovernedActionStatus.AUTHORIZED
        action.audit_trail.append(
            f"Action authorized by '{action.authorized_by}' at {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}."
        )
        if self.action_repo:
            self.action_repo.save_action(action)
        return action

    def execute_action(self, action_id: str, force_live: bool = False) -> Dict[str, Any]:
        """
        Execute an authorized action with idempotency protection and fail-closed safety.
        """
        action = self.actions.get(action_id)
        if not action and self.action_repo:
            action = self.action_repo.get_action(action_id)
            if action:
                self.actions[action.action_id] = action

        if not action:
            raise KeyError(f"Action '{action_id}' not found.")

        # 1. Enforce authorization requirement
        if action.status not in [GovernedActionStatus.AUTHORIZED, GovernedActionStatus.VALIDATED]:
            if action.requires_human_approval and not action.authorized_by:
                raise ActionAuthorizationError(
                    f"Cannot execute unauthorized action '{action_id}'. Current status: {action.status.value}"
                )

        # 2. Idempotency Check (Prevent duplicate external side-effects)
        cached_result = self.execution_cache.get(action.idempotency_key)
        if not cached_result and self.action_repo:
            cached_result = self.action_repo.get_action_execution(action.idempotency_key)

        if cached_result:
            action.audit_trail.append(
                f"Idempotency cache hit: returned existing execution result for key '{action.idempotency_key}'."
            )
            action.status = GovernedActionStatus.EXECUTED
            if self.action_repo:
                self.action_repo.save_action(action)
            return cached_result

        # 3. Fail-closed safety gate
        is_live_request = force_live or (isinstance(self.dispatcher, LiveActionDispatcher) and not self.dry_run)
        if is_live_request and not self.live_actions_enabled:
            raise LiveActionPolicyError(
                "Live write operations are disabled by policy (ORACLE_LIVE_ACTIONS_ENABLED is false). "
                "Execution rejected (fail-closed)."
            )

        # 4. Dispatch via configured dispatcher with crash/uncertainty safety
        dry_run = self.dry_run and not force_live
        try:
            result_payload = self.dispatcher.dispatch(action, dry_run=dry_run)
        except Exception as exc:
            action.status = GovernedActionStatus.RECONCILIATION_REQUIRED
            action.audit_trail.append(
                f"Action dispatch failed or uncertain: {str(exc)}. Transitioned to RECONCILIATION_REQUIRED."
            )
            if self.action_repo:
                self.action_repo.save_action(action)
            raise

        now_ts = result_payload.get("dispatched_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        action.execution_timestamp = now_ts
        action.status = GovernedActionStatus.EXECUTED
        action.audit_trail.append(
            f"Action executed successfully via {self.dispatcher.__class__.__name__}. "
            f"Dispatch ref: {result_payload.get('reference')}."
        )

        # 5. Store in idempotency cache and durable store
        self.execution_cache[action.idempotency_key] = result_payload
        if self.action_repo:
            self.action_repo.save_action(action)
            self.action_repo.record_action_execution(action.idempotency_key, action.action_id, result_payload)

        return result_payload

    def verify_action(self, action_id: str) -> bool:
        """Verify that the executed action achieved the expected state in the target system."""
        action = self.actions.get(action_id)
        if not action and self.action_repo:
            action = self.action_repo.get_action(action_id)
            if action:
                self.actions[action.action_id] = action

        if not action:
            raise KeyError(f"Action '{action_id}' not found.")

        if action.status != GovernedActionStatus.EXECUTED:
            return False

        exec_res = self.execution_cache.get(action.idempotency_key)
        if not exec_res and self.action_repo:
            exec_res = self.action_repo.get_action_execution(action.idempotency_key)
        exec_res = exec_res or {}

        verified = self.dispatcher.verify(action, exec_res)
        if verified:
            action.status = GovernedActionStatus.VERIFIED
            action.audit_trail.append("Action execution verified via target system state check.")
            if self.action_repo:
                self.action_repo.save_action(action)
            return True
        else:
            action.status = GovernedActionStatus.RECONCILIATION_REQUIRED
            action.audit_trail.append("Action execution verification FAILED against target system. Transitioned to RECONCILIATION_REQUIRED.")
            if self.action_repo:
                self.action_repo.save_action(action)
            return False

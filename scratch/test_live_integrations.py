import os
import sys
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

load_dotenv()

from backend.retrieval.adapters.config import JiraConfig, GitHubConfig
from backend.retrieval.adapters.jira import JiraEvidenceProvider
from backend.retrieval.adapters.github import GitHubEvidenceProvider
from backend.retrieval.registry import EvidenceProviderRegistry

print("=" * 60)
print("ORACLE LIVE INTEGRATION VALIDATION SUITE")
print("=" * 60)

# 1. Jira
print("\n[JIRA CLOUD LIVE TEST]")
jira_conf = JiraConfig.from_env()
print(f"Jira Base URL: {jira_conf.base_url}")
print(f"Jira User:     {jira_conf.email_or_username}")
print(f"Jira Projects: {jira_conf.project_keys}")

jira_provider = JiraEvidenceProvider(jira_conf)
is_jira_healthy = jira_provider.health_check()
print(f"Jira Health Check: {'ONLINE (200 OK)' if is_jira_healthy else 'FAILED'}")

try:
    results, latency = jira_provider.search("KAN", k=5)
    print(f"Jira Search Latency: {latency:.2f}ms | Items Retrieved: {len(results)}")
    for ev, score in results:
        key = ev.metadata.get("issue_key") or ev.source_id
        summary = ev.metadata.get("summary") or ev.content[:60]
        status = ev.metadata.get("status") or "Unknown"
        print(f"  * [{key}] ({status}) {summary} (Score: {score:.2f})")
except Exception as e:
    print(f"Jira search error: {e}")

# 2. GitHub
print("\n[GITHUB API LIVE TEST]")
gh_conf = GitHubConfig.from_env()
print(f"GitHub Base URL: {gh_conf.base_url}")
token_preview = gh_conf.api_token[:15] + "..." if gh_conf.api_token else "None"
print(f"GitHub Token:    {token_preview}")

gh_provider = GitHubEvidenceProvider(gh_conf)
is_gh_healthy = gh_provider.health_check()
print(f"GitHub Health Check: {'ONLINE (200 OK)' if is_gh_healthy else 'FAILED'}")

try:
    gh_results, gh_latency = gh_provider.search("fastapi", k=5)
    print(f"GitHub Search Latency: {gh_latency:.2f}ms | Items Retrieved: {len(gh_results)}")
    for ev, score in gh_results:
        title = ev.metadata.get("title") or ev.content[:60]
        url = ev.metadata.get("url") or ev.source_id
        print(f"  * {title} -> {url}")
except Exception as e:
    print(f"GitHub search error: {e}")

# 3. Federated Retrieval Registry Check
print("\n[FEDERATED RETRIEVAL REGISTRY]")
registry = EvidenceProviderRegistry()
registry.register(jira_provider)
registry.register(gh_provider)
active_providers = registry.list_providers()
print(f"Active Registered Providers: {[p.provider_id for p in active_providers]}")
print("=" * 60)

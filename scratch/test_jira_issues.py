import os
import sys
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

load_dotenv()
from backend.retrieval.adapters.config import JiraConfig
from backend.retrieval.adapters.jira import JiraEvidenceProvider

jira_conf = JiraConfig.from_env()
p = JiraEvidenceProvider(jira_conf)
res = p._client.get(f"{jira_conf.base_url}/rest/api/3/search/jql?jql=project=KAN")
data = res.json()
print("=" * 60)
print("REAL LIVE JIRA ISSUES FROM starkindustries4229.atlassian.net:")
print("=" * 60)
for item in data.get("issues", []):
    iid = item["id"]
    issue_res = p._client.get(f"{jira_conf.base_url}/rest/api/3/issue/{iid}")
    if issue_res.status_code == 200:
        iss = issue_res.json()
        key = iss.get("key")
        fields = iss.get("fields", {}) or {}
        summary = fields.get("summary")
        status_obj = fields.get("status") or {}
        status = status_obj.get("name") if isinstance(status_obj, dict) else str(status_obj)
        priority_obj = fields.get("priority") or {}
        priority = priority_obj.get("name") if isinstance(priority_obj, dict) else "None"
        print(f" -> [{key}] ({status} / {priority}): {summary}")
